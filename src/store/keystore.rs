use chacha20::ChaCha8Rng;
use littlefs2::path::PathBuf;

use crate::{
    Bytes,
    error::{Error, Result},
    key,
    Platform,
    store::{self, Store as _},
    types::{KeyId, Location},
};

pub struct ClientKeystore<P>
where
    P: Platform,
{
    client_id: PathBuf,
    rng: ChaCha8Rng,
    store: P::S,
}

impl<P: Platform> ClientKeystore<P> {
    pub fn new(client_id: PathBuf, rng: ChaCha8Rng, store: P::S) -> Self {
        Self { client_id, rng, store }
    }
}

pub const SERIALIZATION_VERSION: u8 = 0;

/// Trait intended for use by mechanism implementations.
pub trait Keystore {
    // fn store(&self, key: Key, location: Location) -> Result<KeyId>;
    // fn load(&self, key: KeyId) -> Result<Key>;
    // fn exists(&self, key: KeyId) -> bool;
    fn store_key(&mut self, location: Location, secrecy: key::Secrecy, info: key::Info, material: &[u8]) -> Result<KeyId>;
    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool;
    /// Return Header of key, if it exists
    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info>;
    fn delete_key(&self, id: &KeyId) -> bool;
    fn delete_all(&self, location: Location) -> Result<usize>;
    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key>;
    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()>;
    fn rng(&mut self) -> &mut ChaCha8Rng;
    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location>;
}

impl<P: Platform> ClientKeystore<P> {

    /// generates a new key ID (retries on collision with an existing key)
    pub fn new_random_key_id(&mut self, secrecy: key::Secrecy) -> KeyId {
	use rand_core::RngCore;

	let mut buf = [0u8; 12];
	let mut keyid: KeyId;
	loop {
		self.rng().fill_bytes(&mut buf);
		keyid = KeyId::new(0u32, &buf);
		if ! self.exists_key(secrecy, None, &keyid) {
			break;
		}
	}
        keyid
    }

    pub fn key_directory(&self, secrecy: key::Secrecy) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(&self.client_id);
        path.push(&match secrecy {
            key::Secrecy::Secret => PathBuf::from("sec"),
            key::Secrecy::Public => PathBuf::from("pub"),
        });
        path
    }

    pub fn key_path(&self, secrecy: key::Secrecy, id: &KeyId) -> PathBuf {
        let mut path = self.key_directory(secrecy);
	const HEX: &[u8] = b"0123456789abcdef";
	let mut objhex: [u8; 24] = [0u8; 24];
	for i in 0..id.0.object_id.len() {
		objhex[2*i] = HEX[(id.0.object_id[i] >> 4) as usize];
		objhex[2*i+1] = HEX[(id.0.object_id[i] & 0xf) as usize];
	}
        path.push(&PathBuf::from(&objhex));
        path
    }

}

impl<P: Platform> Keystore for ClientKeystore<P> {

    fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }

    #[inline(never)]
    fn store_key(&mut self, location: Location, secrecy: key::Secrecy, info: key::Info, material: &[u8]) -> Result<KeyId> {
        // info_now!("storing {:?} -> {:?}", &key_kind, location);

        let mut info: key::Info = info.into();
        if secrecy == key::Secrecy::Secret {
            info.flags |= key::Flags::SENSITIVE;
        }
        let key = key::Key {
            flags: info.flags,
            kind: info.kind,
            material: key::Material::from_slice(material).unwrap(),
        };

        let id = self.new_random_key_id(secrecy);
        let path = self.key_path(secrecy, &id);
        store::store(self.store, location, &path, &key.serialize())?;

        Ok(id)
    }

    fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool {
        self.load_key(secrecy, kind, id).is_ok()
    }

    fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info> {
        self.load_key(secrecy, None, id).map(|key| key::Info { flags: key.flags, kind: key.kind }).ok()
    }

    // TODO: is this an Oracle?
    fn delete_key(&self, id: &KeyId) -> bool {
        let secrecies = [
            key::Secrecy::Secret,
            key::Secrecy::Public,
        ];

        let locations = [
            Location::Internal,
            Location::External,
            Location::Volatile,
        ];

        secrecies.iter().any(|secrecy| {
            let path = self.key_path(*secrecy, &id);
            locations.iter().any(|location| {
                store::delete(self.store, *location, &path)
            })
        })
    }

    /// TODO: This uses the predicate "filename.len() >= 4"
    /// Be more principled :)
    fn delete_all(&self, location: Location) -> Result<usize> {
        let path = self.key_directory(key::Secrecy::Secret);
        store::remove_dir_all_where(self.store, location, &path, |dir_entry| {
            dir_entry.file_name().as_ref().len() >= 4
        })?;
        let path = self.key_directory(key::Secrecy::Public);
        store::remove_dir_all_where(self.store, location, &path, |dir_entry| {
            dir_entry.file_name().as_ref().len() >= 4
        })
    }

    fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key> {
        // info_now!("loading  {:?}", &key_kind);
        let path = self.key_path(secrecy, id);

        let location = self.location(secrecy, id).ok_or(Error::NoSuchKey)?;

        let bytes: Bytes<128> = store::read(self.store, location, &path)?;

        let key = key::Key::try_deserialize(&bytes)?;

        if let Some(kind) = kind {
            if key.kind != kind {
                return Err(Error::WrongKeyKind);
            }
        }
        Ok(key)
    }

    fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()> {
        let mut flags = key::Flags::default();
        if secrecy == key::Secrecy::Secret {
            flags |= key::Flags::SENSITIVE;
        }
        let key = key::Key {
            flags: Default::default(),
            kind,
            material: key::Material::from_slice(material).unwrap(),
        };

        let path = self.key_path(secrecy, id);
        store::store(self.store, location, &path, &key.serialize())?;

        Ok(())
    }


    fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location> {
        let path = self.key_path(secrecy, id);

        if path.exists(&self.store.vfs()) {
            return Some(Location::Volatile);
        }

        if path.exists(&self.store.ifs()) {
            return Some(Location::Internal);
        }

        if path.exists(&self.store.efs()) {
            return Some(Location::External);
        }

        None
    }

}

pub struct AbstractKeystore<P> where P: Platform {
    software: ClientKeystore<P>,
    #[cfg(feature = "hwcrypto-se050")]
    se050: Option<crate::hwcrypto::se050::Se050Keystore>,
}

impl<P> AbstractKeystore<P> where P: Platform {
    fn provider_from_keyid(&self, id: &KeyId) -> Option<&dyn Keystore> {
        if id.0.provider_id == 0u32 {
            return Some(&self.software)
        }
        #[cfg(feature = "hwcrypto-se050")]
        if id.0.provider_id == crate::hwcrypto::se050::SE050_PROVIDER_ID {
            match &self.se050 {
            Some(se050_prov) => { return Some(se050_prov as &dyn Keystore); },
            None => { return None; }
            }
        }
        None
    }

    fn provider_from_keyid_mut(&mut self, id: &KeyId) -> Option<&mut dyn Keystore> {
        if id.0.provider_id == 0u32 {
            return Some(&mut self.software)
        }
        #[cfg(feature = "hwcrypto-se050")]
        if id.0.provider_id == crate::hwcrypto::se050::SE050_PROVIDER_ID {
            match &mut self.se050 {
            Some(se050_prov) => { return Some(se050_prov as &mut dyn Keystore); },
            None => { return None; }
            }
        }
        None
    }

    // store_key() intentionally not implemented for AbstractKeystore!

    pub fn exists_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> bool {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.exists_key(secrecy, kind, id)
        } else {
            false
        }
    }

    pub fn key_info(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<key::Info> {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.key_info(secrecy, id)
        } else {
            None
        }
    }

    pub fn delete_key(&self, id: &KeyId) -> bool {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.delete_key(id)
        } else {
            false
        }
    }

    pub fn delete_all(&self, location: Location) -> Result<usize> {
        let mut count: usize = 0;
        if let Ok(cnt) = self.software.delete_all(location) {
            count += cnt;
        }
        #[cfg(feature = "hwcrypto-se050")]
        if let Some(se050_provider) = &self.se050 {
            if let Ok(cnt) = se050_provider.delete_all(location) {
                count += cnt;
            }
        }
        Ok(count)
    }

    pub fn load_key(&self, secrecy: key::Secrecy, kind: Option<key::Kind>, id: &KeyId) -> Result<key::Key> {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.load_key(secrecy, kind, id)
        } else {
            Err(Error::NoSuchKey)
        }
    }

    pub fn overwrite_key(&self, location: Location, secrecy: key::Secrecy, kind: key::Kind, id: &KeyId, material: &[u8]) -> Result<()> {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.overwrite_key(location, secrecy, kind, id, material)
        } else {
            Err(Error::NoSuchKey)
        }
    }

    pub fn location(&self, secrecy: key::Secrecy, id: &KeyId) -> Option<Location> {
        let provider = self.provider_from_keyid(id);
        if let Some(prov) = provider {
            prov.location(secrecy, id)
        } else {
            None
        }
    }

}
