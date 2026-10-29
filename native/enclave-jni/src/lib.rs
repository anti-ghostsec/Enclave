//! JNI bridge: lets the app keep its vault inside deniable containers.
//!
//! Each container is opened as a handle (a boxed, locked [`Store`]) that the
//! app keeps as a `long`. Volumes are only ever unlocked or created with a key
//! the app derives itself, never a password, so the crate's Argon2 cost is
//! never paid here. Errors become `java.io.IOException`s; a full container
//! says "container full" so the app can move on to the next one.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use deniable::{BlockDevice, Error, FileDevice, Kdf, Store, VolumeId};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

struct Inner {
    /// None once closed: the keys and the file are gone, and every call fails cleanly.
    store: Option<Store<FileDevice>>,
    /// The app refers to volumes by their position in this list.
    ids: Vec<VolumeId>,
}

impl Inner {
    fn index_of(&mut self, id: VolumeId) -> jint {
        match self.ids.iter().position(|v| *v == id) {
            Some(i) => i as jint,
            None => {
                self.ids.push(id);
                (self.ids.len() - 1) as jint
            }
        }
    }

    fn id(&self, v: jint) -> Result<VolumeId, String> {
        self.ids.get(v as usize).copied().ok_or_else(|| "no such volume".to_string())
    }

    fn store(&mut self) -> Result<&mut Store<FileDevice>, String> {
        self.store.as_mut().ok_or_else(|| "container is closed".to_string())
    }
}

struct Container {
    inner: Mutex<Inner>,
    blocks: u64,
}

impl Container {
    fn lock(&self) -> Result<MutexGuard<'_, Inner>, String> {
        self.inner.lock().map_err(|_| "storage lock poisoned".to_string())
    }
}

/// Runs `f`, turning errors and panics into a Java exception and `fallback`.
fn guard<T>(env: &mut JNIEnv, fallback: T, f: impl FnOnce(&mut JNIEnv) -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(|| f(env))) {
        Ok(Ok(v)) => v,
        Ok(Err(msg)) => {
            let _ = env.throw_new("java/io/IOException", msg);
            fallback
        }
        Err(_) => {
            let _ = env.throw_new("java/io/IOException", "internal error in deniable storage");
            fallback
        }
    }
}

fn describe(e: Error) -> String {
    match e {
        Error::Full => "container full".into(),
        other => other.to_string(),
    }
}

fn container<'a>(handle: jlong) -> Result<&'a Container, String> {
    if handle == 0 {
        return Err("container is closed".into());
    }
    // SAFETY: handles come only from `into_handle` and stay valid until `close`.
    Ok(unsafe { &*(handle as *const Container) })
}

fn into_handle(store: Store<FileDevice>, blocks: u64) -> jlong {
    Box::into_raw(Box::new(Container { inner: Mutex::new(Inner { store: Some(store), ids: Vec::new() }), blocks })) as jlong
}

fn key(env: &mut JNIEnv, array: &JByteArray) -> Result<[u8; 32], String> {
    let mut bytes = env.convert_byte_array(array).map_err(|e| e.to_string())?;
    let out: Result<[u8; 32], _> = bytes.as_slice().try_into();
    bytes.iter_mut().for_each(|b| *b = 0);
    out.map_err(|_| "key must be 32 bytes".to_string())
}

fn path(env: &mut JNIEnv, p: &JString) -> Result<String, String> {
    Ok(env.get_string(p).map_err(|e| e.to_string())?.into())
}

/// Makes a new container file of `blocks` blocks, filled with random bytes.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_format(mut env: JNIEnv, _: JClass, file: JString, blocks: jlong) -> jlong {
    guard(&mut env, 0, |env| {
        let p = path(env, &file)?;
        let dev = FileDevice::create(Path::new(&p), blocks as u64).map_err(|e| e.to_string())?;
        let store = Store::format(dev, Kdf::DEFAULT).map_err(describe)?;
        Ok(into_handle(store, blocks as u64))
    })
}

/// Opens an existing container with nothing unlocked.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_open(mut env: JNIEnv, _: JClass, file: JString) -> jlong {
    guard(&mut env, 0, |env| {
        let p = path(env, &file)?;
        let dev = FileDevice::open(Path::new(&p)).map_err(|e| e.to_string())?;
        let blocks = dev.blocks();
        let store = Store::open(dev, Kdf::DEFAULT).map_err(describe)?;
        Ok(into_handle(store, blocks))
    })
}

/// Forgets every key and closes the file. Unflushed changes are dropped. The handle itself
/// stays allocated (a few bytes), so a read still running on another thread fails cleanly
/// instead of touching freed memory.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_close(mut env: JNIEnv, _: JClass, handle: jlong) {
    guard(&mut env, (), |_| {
        let mut inner = container(handle)?.lock()?;
        inner.store = None;
        inner.ids.clear();
        Ok(())
    })
}

#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_blocks(mut env: JNIEnv, _: JClass, handle: jlong) -> jlong {
    guard(&mut env, 0, |_| Ok(container(handle)?.blocks as jlong))
}

/// The volume this key opens, or -1 if there's none.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_unlock(mut env: JNIEnv, _: JClass, handle: jlong, k: JByteArray) -> jint {
    guard(&mut env, -1, |env| {
        let key = key(env, &k)?;
        let mut inner = container(handle)?.lock()?;
        match inner.store()?.unlock_key(&key) {
            Ok(id) => Ok(inner.index_of(id)),
            Err(Error::NotFound) => Ok(-1),
            Err(e) => Err(describe(e)),
        }
    })
}

/// Makes a new, empty volume opened by this key.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_create(mut env: JNIEnv, _: JClass, handle: jlong, k: JByteArray) -> jint {
    guard(&mut env, -1, |env| {
        let key = key(env, &k)?;
        let mut inner = container(handle)?.lock()?;
        let id = inner.store()?.create_key(&key, &[]).map_err(describe)?;
        Ok(inner.index_of(id))
    })
}

#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_len(mut env: JNIEnv, _: JClass, handle: jlong, v: jint) -> jlong {
    guard(&mut env, -1, |_| {
        let mut inner = container(handle)?.lock()?;
        let id = inner.id(v)?;
        inner.store()?.len(id).map(|n| n as jlong).map_err(describe)
    })
}

/// Reads up to `len` bytes at `offset` into `buf[off..]`. Returns bytes read.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_read(
    mut env: JNIEnv,
    _: JClass,
    handle: jlong,
    v: jint,
    offset: jlong,
    buf: JByteArray,
    off: jint,
    len: jint,
) -> jint {
    guard(&mut env, -1, |env| {
        let mut tmp = vec![0u8; len.max(0) as usize];
        let n = {
            let mut inner = container(handle)?.lock()?;
            let id = inner.id(v)?;
            inner.store()?.read(id, offset as u64, &mut tmp).map_err(describe)?
        };
        let mut signed: Vec<i8> = tmp[..n].iter().map(|&b| b as i8).collect();
        tmp.iter_mut().for_each(|b| *b = 0);
        let r = env.set_byte_array_region(&buf, off, &signed).map_err(|e| e.to_string());
        signed.iter_mut().for_each(|b| *b = 0);
        r?;
        Ok(n as jint)
    })
}

/// Writes `buf[off..off+len]` at `offset`. Kept only after `flush`.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_write(
    mut env: JNIEnv,
    _: JClass,
    handle: jlong,
    v: jint,
    offset: jlong,
    buf: JByteArray,
    off: jint,
    len: jint,
) {
    guard(&mut env, (), |env| {
        let mut signed = vec![0i8; len.max(0) as usize];
        env.get_byte_array_region(&buf, off, &mut signed).map_err(|e| e.to_string())?;
        let mut data: Vec<u8> = signed.iter().map(|&b| b as u8).collect();
        signed.iter_mut().for_each(|b| *b = 0);
        let r = {
            let mut inner = container(handle)?.lock()?;
            let id = inner.id(v)?;
            inner.store()?.write(id, offset as u64, &data).map_err(describe)
        };
        data.iter_mut().for_each(|b| *b = 0);
        r
    })
}

#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_setLen(mut env: JNIEnv, _: JClass, handle: jlong, v: jint, len: jlong) {
    guard(&mut env, (), |_| {
        let mut inner = container(handle)?.lock()?;
        let id = inner.id(v)?;
        inner.store()?.set_len(id, len as u64).map_err(describe)
    })
}

/// Saves every changed volume in this container. Each volume's save is atomic.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_flush(mut env: JNIEnv, _: JClass, handle: jlong) {
    guard(&mut env, (), |_| container(handle)?.lock()?.store()?.flush().map_err(describe))
}

/// Overwrites every block of the volume with random bytes and forgets it.
#[no_mangle]
pub extern "system" fn Java_app_enclave_vault_Native_destroy(mut env: JNIEnv, _: JClass, handle: jlong, v: jint) {
    guard(&mut env, (), |_| {
        let mut inner = container(handle)?.lock()?;
        let id = inner.id(v)?;
        inner.store()?.destroy(id).map_err(describe)
    })
}
