use adnl::{
    common::{
        add_object_to_map, add_object_to_map_with_update, AdnlPeers, deserialize, get256, 
        hash, hash_boxed, KeyId, KeyOption, Query, QueryResult, serialize, serialize_inplace, 
        Subscriber, Version, Wait
    }, 
    node::{AddressCache, AddressCacheIterator, AdnlNode, IpAddress}
};
use overlay::{OverlayId, OverlayShortId, OverlayUtils};
use rand::Rng;
use std::{mem, ops::Deref, sync::Arc};
use ton_api::{
    IntoBoxed, 
    ton::{
        self, PublicKey, TLObject, 
        adnl::{AddressList as AddressListBoxed, addresslist::AddressList}, 
        dht::{
            Node as NodeBoxed, Nodes as NodesBoxed, Pong as DhtPongBoxed, Stored, UpdateRule,
            ValueResult as DhtValueResult,
            key::Key as DhtKey, keydescription::KeyDescription as DhtKeyDescription, 
            node::Node, nodes::Nodes, pong::Pong as DhtPong, value::Value as DhtValue,
            valueresult::{ValueFound, ValueNotFound}
        },
        overlay::{
            Nodes as OverlayNodesBoxed, node::Node as OverlayNode, nodes::Nodes as OverlayNodes
        }, 
        pub_::publickey::{Ed25519, Overlay},
        rpc::dht::{
            FindNode, FindValue, GetSignedAddressList, Ping as DhtPing, Query as DhtQuery, 
            Store
        }
    }
};
use ton_types::{error, fail, Result};

pub const TARGET: &str = "dht";

#[macro_export]
macro_rules! sign {
    ($data:expr, $key:expr) => {
        {
            let data = $data.into_boxed();
            let mut buf = serialize(&data)?;
            let signature = $key.sign(&buf)?;
            buf.truncate(0);
            buf.extend_from_slice(&signature);
            let mut data = data.only();
            mem::replace(&mut data.signature.0, buf);
            data
        }
    }
}

#[macro_export]
macro_rules! verify {
    ($data:expr, $key:ident) => {
        {
            let signature = mem::replace(&mut $data.signature.0, Vec::new());
            let data = $data.into_boxed();
            let buf = serialize(&data)?;
            $key.verify(&buf[..], &signature[..])?;
            data.only()
        }
    }
}

pub fn build_dht_node_info(ip: &str, key: &str, signature: &str) -> Result<Node> {
    let key = base64::decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let addrs = vec![IpAddress::from_string(ip)?.into_udp().into_boxed()];
    let signature = base64::decode(signature)?;
    let node = Node {
        id: Ed25519 {
            key: ton::int256(arrayref::array_ref!(&key, 0, 32).clone())
        }.into_boxed(),
        addr_list: AddressList {
            addrs: addrs.into(),
            version: 0,
            reinit_date: 0,
            priority: 0,
            expire_at: 0
        },
        version: -1,
        signature: ton::bytes(signature)
    };
    Ok(node)
}

type DhtKeyId = [u8; 32];

/// DHT Node
pub struct DhtNode {
    adnl: Arc<AdnlNode>,
    buckets: lockfree::map::Map<u8, lockfree::map::Map<Arc<KeyId>, Node>>,
    known_peers: AddressCache,
    node_key: Arc<KeyOption>,
    query_prefix: Vec<u8>,
    storage: lockfree::map::Map<DhtKeyId, DhtValue>
}

impl DhtNode {

    const BITS: [u8; 16] = [
        4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0
    ];

    const MAX_PEERS: u32 = 65536;
    const MAX_TASKS: usize = 5; 
    const TIMEOUT_VALUE: i32 = 3600; // Seconds

    /// Constructor 
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, key_tag: usize) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        let mut ret = Self {
            adnl,
            buckets: lockfree::map::Map::new(),
            known_peers: AddressCache::with_limit(Self::MAX_PEERS),
            node_key,
            query_prefix: Vec::new(),
            storage: lockfree::map::Map::new(),
        };
        let query = DhtQuery { 
            node: ret.sign_local_node()? 
        };
        serialize_inplace(&mut ret.query_prefix, &query)?;
        Ok(Arc::new(ret))
    }

    /// Add DHT peer 
    pub fn add_peer(&self, peer: &Node) -> Result<Option<Arc<KeyId>>> {
        if let Err(e) = self.verify_other_node(peer) {
            log::warn!(target: TARGET, "Error when verifying DHT peer: {}", e);
            return Ok(None)
        }
        let ret = self.adnl.add_peer(
            self.node_key.id(), 
            &AdnlNode::parse_address_list(&peer.addr_list)?, 
            &Arc::new(KeyOption::from_tl_public_key(&peer.id)?)
        )?;
        let ret = if let Some(ret) = ret {
            ret
        } else {
            return Ok(None)
        };
        if self.known_peers.put(ret.clone())? {
            let key1 = self.node_key.id().data();
            let key2 = ret.data();
            let mut dist = 0;
            for i in 0..32 {
                match key1[i] ^ key2[i] {
                    0 => dist += 8,
                    x => {
                        if (x & 0xF0) == 0 {
                            dist += Self::BITS[(x & 0x0F) as usize] + 4
                        } else {
                            dist += Self::BITS[(x >> 4) as usize]
                        }
                        break
                    }
                }
            }
            add_object_to_map(
                &self.buckets, 
                dist, 
                || Ok(lockfree::map::Map::new())
            )?;
            if let Some(bucket) = self.buckets.get(&dist) {
                add_object_to_map_with_update(
                    bucket.val(),
                    ret.clone(), 
                    |old_node| if let Some(old_node) = old_node {
                        if old_node.version < peer.version {
                            Ok(Some(peer.clone()))
                        } else {
                            Ok(None)
                        }
                    } else {
                        Ok(Some(peer.clone()))
                    }
                )?;
            }
        }
        Ok(Some(ret))
    }

    /// Find DHT nodes
    pub async fn find_dht_nodes(&self, dst: &Arc<KeyId>) -> Result<bool> {
        let query = FindNode {
            key: ton::int256(self.node_key.id().data().clone()),
            k: 10
        };
        let query = TLObject::new(query);
        let answer = self.query_with_prefix(dst, &query).await?;
        let answer: NodesBoxed = if let Some(answer) = answer {
            Query::parse(answer, &query)?
        } else {
            return Ok(false)
        };        
        let src = answer.only().nodes;
        log::debug!(target: TARGET, "-------- Found DHT nodes:");
        for node in src.deref() {
            log::debug!(target: TARGET, "{:?}", node);
            self.add_peer(node)?; 
        }
        Ok(true)
    }

    /// Find address of node with given key ID 
    pub async fn find_address(
        dht: &Arc<Self>, 
        key_id: &Arc<KeyId>
    ) -> Result<(IpAddress, KeyOption)> {
        let mut addr_list = DhtNode::find_value(
            dht, 
            Self::dht_key_from_key_id(key_id, "address"),
            |object| object.is::<AddressListBoxed>(),
            false, 
            &mut None
        ).await?;
        if let Some((key, addr_list)) = addr_list.pop() {
            if let Ok(addr_list) = addr_list.downcast::<AddressListBoxed>() {
                let ip_address = AdnlNode::parse_address_list(&addr_list.only())?;
                let key = KeyOption::from_tl_public_key(&key.id)?;
                Ok((ip_address, key))
            } else {
                fail!("INTERNAL ERROR: address list type mismatch in search")
            }
        } else {
            fail!("No address found for {}", key_id)
        }
    }

    /// Get nodes of overlay with given ID
    pub async fn find_overlay_nodes(
        dht: &Arc<Self>, 
        overlay_id: &Arc<OverlayShortId>,
        iter: &mut Option<AddressCacheIterator>
    ) -> Result<Vec<(IpAddress, OverlayNode)>> {
        let mut nodes_lists = DhtNode::find_value(
            dht, 
            Self::dht_key_from_key_id(overlay_id, "nodes"),
            |object| object.is::<OverlayNodesBoxed>(),
            true, 
            iter
        ).await?;
        let mut ret = Vec::new();
        if nodes_lists.is_empty() {
            return Ok(ret)   
        }
        log::debug!(target: TARGET, "-------- Found Overlay node keys:");
        let mut nodes = Vec::new();
        while let Some((_, nodes_list)) = nodes_lists.pop() {
            if let Ok(nodes_list) = nodes_list.downcast::<OverlayNodesBoxed>() {
                nodes.append(&mut nodes_list.only().nodes.0)
            } else {
                fail!("INTERNAL ERROR: overlay nodes list type mismatch in search")
            } 
        }
        let (wait, mut queue_reader) = Wait::new();
        let cache = AddressCache::with_limit(Self::MAX_PEERS);
        while let Some(node) = nodes.pop() {
            let key = KeyOption::from_tl_public_key(&node.id)?;
            if !cache.put(key.id().clone())? {
                continue
            }
            let dht = dht.clone();  
            let wait = wait.clone();
            wait.request();
            tokio::spawn(
                async move {
                    if let Ok((ip, _)) = DhtNode::find_address(&dht, key.id()).await {
                        log::debug!(
                            target: TARGET, 
                            "-------- Got Overlay node {} IP: {}", 
                            key.id(), ip
                        );
                        wait.respond(Some((ip, node)))
                    } else {
                        wait.respond(None) 
                    }
                }
            );
        }
        loop {  
            match wait.wait(&mut queue_reader, false).await { 
                Some(None) => (),
                Some(Some(item)) => ret.push(item),
                None => break
            }
        }
        Ok(ret)
    }

    /// Get known DHT nodes
    pub fn get_known_nodes(&self, limit: usize) -> Result<Vec<Node>> {
        if limit == 0 {
            fail!("It is useless to ask for zero known nodes")
        }
        let mut ret = Vec::new();
        for i in 0..=255 {
            if let Some(bucket) = self.buckets.get(&i) {
                for node in bucket.val().iter() {         
                    ret.push(node.val().clone());
                    if ret.len() == limit {
                        return Ok(ret)
                    }
                }
            }
        }
        Ok(ret)
    }
                    
    /// Get signed address list 
    pub async fn get_signed_address_list(&self, dst: &Arc<KeyId>) -> Result<bool> {
        let query = TLObject::new(GetSignedAddressList);
        let answer = self.query_with_prefix(dst, &query).await?;
        let answer: NodeBoxed = if let Some(answer) = answer {
            Query::parse(answer, &query)?
        } else {
            return Ok(false)
        };
        self.add_peer(&answer.only())?;
        Ok(true)
    }

    /// Get signed node
    pub fn get_signed_node(&self) -> Result<Node> {
        self.sign_local_node()
    }

    /// Node IP address
    pub fn ip_address(&self) -> &IpAddress {
        self.adnl.ip_address()
    }

    /// Node key
    pub fn key(&self) -> &Arc<KeyOption> {
        &self.node_key
    }

    /// Ping 
    pub async fn ping(&self, dst: &Arc<KeyId>) -> Result<bool> {
        let random_id = rand::thread_rng().gen();
        let query = TLObject::new(
            DhtPing { 
                random_id 
            }
        );
        let answer = self.query(dst, &query).await?;
        let answer: DhtPongBoxed = if let Some(answer) = answer {
            Query::parse(answer, &query)?
        } else {
            return Ok(false)
        };
        Ok(answer.random_id() == &random_id)
    }

    /// Store own IP address
    pub async fn store_ip_address(dht: &Arc<Self>) -> Result<bool> {
        log::debug!(target: TARGET, "Storing key ID {}", dht.node_key.id());
        let value = serialize(&dht.adnl.build_address_list(0)?.into_boxed())?;
        Self::store_value(
            dht,
            Self::dht_key_from_key_id(dht.node_key.id(), "address"),
            dht.sign_value("address", &value[..])?,
            |object| object.is::<AddressListBoxed>(),
            false, 
            |mut objects| {
                while let Some((_, object)) = objects.pop() {
                    if let Ok(addr_list) = object.downcast::<AddressListBoxed>() {
                        let ip = AdnlNode::parse_address_list(&addr_list.only())?;
                        if &ip == dht.adnl.ip_address() {
                            log::debug!(target: TARGET, "Checked stored address {:?}", ip);
                            return Ok(true);
                        } else {
                            log::warn!(
                                target: TARGET, 
                                "Found another stored address {:?}, expected {:?}", 
                                ip,
                                dht.adnl.ip_address()
                            )
                        }
                    } else {
                        fail!("INTERNAL ERROR: address list type mismatch in store")
                    }
                }
                Ok(false)
            }
        ).await
    }

    /// Store own overlay node
    pub async fn store_overlay_node(
        dht: &Arc<Self>, 
        overlay_id: &OverlayId, 
        node: &OverlayNode
    ) -> Result<bool> {
        log::debug!(target: TARGET, "Storing overlay node {:?}", node);
        let overlay_id = Overlay {
            name: ton::bytes(overlay_id.to_vec())
        };
        let overlay_short_id = OverlayShortId::from_data(hash(overlay_id.clone())?);
        OverlayUtils::verify_node(&overlay_short_id, node)?;
        let nodes = OverlayNodes {
            nodes: vec![node.clone()].into()
        }.into_boxed();
        let key = Self::dht_key_from_key_id(&overlay_short_id, "nodes");
        let value = DhtValue {
            key: DhtKeyDescription {
                id: overlay_id.into_boxed(),
                key: key.clone(),
                signature: ton::bytes::default(),
                update_rule: UpdateRule::Dht_UpdateRule_OverlayNodes
            },
            ttl: Version::get() + Self::TIMEOUT_VALUE,
            signature: ton::bytes::default(),
            value: ton::bytes(serialize(&nodes)?)
        };
        Self::store_value(
            dht,
            key,
            value,
            |object| object.is::<OverlayNodesBoxed>(),
            true, 
            |mut objects| {
                while let Some((_, object)) = objects.pop() {
                    if let Ok(nodes_list) = object.downcast::<OverlayNodesBoxed>() {
                        for found_node in nodes_list.only().nodes.0 {
                            if &found_node == node {
                                log::debug!(target: TARGET, "Checked stored node {:?}", node);
                                return Ok(true);
                            }
                        }
                    } else {
                        fail!("INTERNAL ERROR: overlay nodes list type mismatch in store")
                    }
                }
                Ok(false)
            }
        ).await
    }

    fn deserialize_overlay_nodes(value: &[u8]) -> Result<Vec<OverlayNode>> {
        let nodes = deserialize(value)?
            .downcast::<OverlayNodesBoxed>()
            .map_err(|object| error!("Wrong OverlayNodes: {:?}", object))?;
        Ok(nodes.only().nodes.0)
    }

    fn dht_key_from_key_id(id: &Arc<KeyId>, name: &str) -> DhtKey {
        DhtKey {
            id: ton::int256(id.data().clone()),
            idx: 0,
            name: ton::bytes(name.as_bytes().to_vec())
        }
    }

    async fn find_value(
        dht: &Arc<Self>, 
        key: DhtKey, 
        check: impl Fn(&TLObject) -> bool + Copy + Send + 'static,
        all: bool,
        iter: &mut Option<AddressCacheIterator>
    ) -> Result<Vec<(DhtKeyDescription, TLObject)>> {
        let key = hash(key)?;
        let query = TLObject::new(
            FindValue { 
                key: ton::int256(key.clone()),
                k: 6 
            }
        );
        let mut current = None; 
        let iter = iter.get_or_insert_with(
            || {
                let (iter, first) = dht.known_peers.first();
                current.replace(first);
                iter   
            } 
        );
        let current = current.get_or_insert_with(|| dht.known_peers.next(iter)); 
        let key = KeyId::from_data(key); 
        let query = Arc::new(query);
        let (wait, mut queue_reader) = Wait::new();  
        let mut ret = Vec::new();
        log::debug!(target: TARGET, "FindValue {} query", key);
        loop {
            while let Some(peer) = current {
                let dht_cloned = dht.clone();
                let key = key.clone();  
                let peer = peer.clone(); 
                let query = query.clone(); 
                let wait = wait.clone(); 
                let reqs = wait.request(); 
                tokio::spawn(
                    async move {
                        match dht_cloned.value_query(&peer, &query, &key, check).await {
                            Ok(found) => wait.respond(found),
                            Err(e) => {
                                log::warn!(target: TARGET, "ERROR: {}", e);
                                wait.respond(None)
                            }
                        } 
                    } 
                );
                *current = dht.known_peers.next(iter);
                if reqs >= Self::MAX_TASKS {
                    break;
                } 
            } 
            log::debug!(
                target: TARGET, 
                "FindValue {} query, {} parallel reqs, iter {:?}", 
                key, wait.count(), iter
            );
            let mut finished = false; 
            loop {
                match wait.wait(&mut queue_reader, !all).await { 
                    Some(None) => (),
                    Some(Some(val)) => ret.push(val),
                    None => {
                        finished = true;
                    }
                }
                // Add more tasks if required 
                if (all && (ret.len() < Self::MAX_TASKS)) || !all || finished {
                    break
                }
            }
            // Stop if possible 
            if (all && (ret.len() >= Self::MAX_TASKS)) || (!all && !ret.is_empty()) || finished {
                break
            } 
            if current.is_none() {
                *current = dht.known_peers.given(iter);
            }                
        }
        Ok(ret)
    }

    fn process_find_node(&self, query: &FindNode) -> Result<Nodes> {
        let key1 = self.node_key.id().data();
        let key2 = get256(&query.key);
        let mut dist = 0;
        let mut ret = Vec::new();
        for i in 0..32 {
            if ret.len() == query.k as usize {
                break;
            }
            let mut subdist = dist;
            let mut xor = key1[i] ^ key2[i];
            while xor != 0 {
                if (xor & 0xF0) == 0 {
                    subdist += 4;
                    xor <<= 4;
                } else {
                    let shift = Self::BITS[(xor >> 4) as usize];
                    subdist += shift;
                    if let Some(bucket) = self.buckets.get(&subdist) {
                        for node in bucket.val().iter() {         
                            ret.push(node.val().clone());
                            if ret.len() == query.k as usize {
                                break
                            }
                        }
                    }
                    xor <<= shift + 1;
                    subdist += 1;
                }
                if ret.len() == query.k as usize {
                    break
                }
            }
            dist += 8;
        }
        let ret = Nodes {
            nodes: ret.into()
        };
        Ok(ret)
    }

    fn process_find_value(&self, query: &FindValue) -> Result<DhtValueResult> {
        let version = Version::get();
        let value = if let Some(value) = self.storage.get(get256(&query.key)) {
            if value.val().ttl > version {
                Some(value)
            } else {
                None
            }
        } else {
            None
        };
        let ret = if let Some(value) = value {
            ValueFound {
                value: value.val().clone().into_boxed()
            }.into_boxed()
        } else {
            ValueNotFound {
                nodes: Nodes {
                    nodes: self.get_known_nodes(query.k as usize)?.into()
                }
            }.into_boxed()
        };
        Ok(ret)
    }

    fn process_ping(&self, query: &DhtPing) -> Result<DhtPong> {
        Ok(DhtPong { random_id: query.random_id })
    }

    fn process_store(&self, query: Store) -> Result<Stored> {
        let dht_key_id = hash(query.value.key.key.clone())?;
        if query.value.ttl <= Version::get() {
            fail!("Ignore expired DHT value with key {}", base64::encode(&dht_key_id))
        }
        match query.value.key.update_rule {
            UpdateRule::Dht_UpdateRule_Signature => 
                self.process_store_signed_value(dht_key_id, query.value)?,
            UpdateRule::Dht_UpdateRule_OverlayNodes =>
                self.process_store_overlay_nodes(dht_key_id, query.value)?,
            _ => fail!("Unsupported store query {:?}", query)  
        };                                                                                                                         
        Ok(Stored::Dht_Stored)
    }

    fn process_store_overlay_nodes(&self, dht_key_id: DhtKeyId, value: DhtValue) -> Result<bool> {
        if value.signature.deref().len() != 0 {
            fail!("Wrong value signature for OverlayNodes")
        }
        if value.key.signature.deref().len() != 0 {
            fail!("Wrong key signature for OverlayNodes")
        }
        let overlay_short_id = match value.key.id {
            PublicKey::Pub_Overlay(_) => OverlayShortId::from_data(hash_boxed(&value.key.id)?),
            _ => fail!("Wrong key description format for OverlayNodes")
        };
        if Self::dht_key_from_key_id(&overlay_short_id, "nodes") != value.key.key {
            fail!("Wrong DHT key for OverlayNodes")
        }
        let mut nodes_list = Self::deserialize_overlay_nodes(&value.value)?;
        let mut nodes = Vec::new();
        while let Some(node) = nodes_list.pop() {
            if let Err(e) = OverlayUtils::verify_node(&overlay_short_id, &node) {
                log::warn!(target: TARGET, "Bad overlay node {:?}: {}", node, e)
            } else {
                nodes.push(node)
            }
        }
        if nodes.is_empty() {
            fail!("Empty overlay nodes list")
        }
        add_object_to_map_with_update(
            &self.storage,
            dht_key_id, 
            |old_value| {
                let old_value = if let Some(old_value) = old_value {
                    if old_value.ttl < Version::get() {
                        None
                    } else if old_value.ttl >= value.ttl {
                        return Ok(None)
                    } else {
                        Some(&old_value.value)
                    }
                } else {
                    None
                };
                let mut old_nodes = if let Some(old_value) = old_value {
                    Self::deserialize_overlay_nodes(old_value)?
                } else {
                    Vec::new()
                };
                for node in nodes.iter() {
                    let mut found = false;
                    for old_node in old_nodes.iter_mut() {
                        if (node.id == old_node.id) && (node.version > old_node.version) {
                            *old_node = node.clone();
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        old_nodes.push(node.clone())
                    }
                } 
                let nodes = OverlayNodes {
                    nodes: old_nodes.into()
                }.into_boxed();
                let mut ret = value.clone();
                ret.value = ton::bytes(serialize(&nodes)?);
                Ok(Some(ret))
            }
        )
    }

    fn process_store_signed_value(&self, dht_key_id: DhtKeyId, value: DhtValue) -> Result<bool> {
        self.verify_value(&value)?;
        add_object_to_map_with_update(
            &self.storage,
            dht_key_id, 
            |old_value| if let Some(old_value) = old_value {
                if old_value.ttl < value.ttl {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(Some(value.clone()))
            }
        )
    }

    async fn query(&self, dst: &Arc<KeyId>, query: &TLObject) -> Result<Option<TLObject>> {
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        self.adnl.query(query, &peers, None).await
    } 

    async fn query_with_prefix(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TLObject
    ) -> Result<Option<TLObject>> {
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        self.adnl.query_with_prefix(Some(&self.query_prefix[..]), query, &peers, None).await
    } 
    
    fn sign_key_description(&self, name: &str) -> Result<DhtKeyDescription> {
        let key_description = DhtKeyDescription {
            id: self.node_key.into_tl_public_key()?,
            key: Self::dht_key_from_key_id(self.node_key.id(), name),
            signature: ton::bytes::default(),
            update_rule: UpdateRule::Dht_UpdateRule_Signature
        };
        Ok(sign!(key_description, self.node_key))
    }    

    fn sign_local_node(&self) -> Result<Node> {
        let local_node = Node {
            id: self.node_key.into_tl_public_key()?,
            addr_list: self.adnl.build_address_list(0)?,
            signature: ton::bytes::default(),
            version: Version::get()
        };
        Ok(sign!(local_node, self.node_key))
    }

    fn sign_value(&self, name: &str, value: &[u8]) -> Result<DhtValue> {
        let value = DhtValue {
            key: self.sign_key_description(name)?,
            ttl: Version::get() + Self::TIMEOUT_VALUE,
            signature: ton::bytes::default(),
            value: ton::bytes(value.to_vec())
        };
        Ok(sign!(value, self.node_key))
    }

    async fn store_value(
        dht: &Arc<Self>, 
        key: DhtKey, 
        value: DhtValue,
        check_type: impl Fn(&TLObject) -> bool + Copy + Send + 'static,
        check_all: bool,
        check_vals: impl Fn(Vec<(DhtKeyDescription, TLObject)>) -> Result<bool>
    ) -> Result<bool> {
        let query = Store {
            value
        };
        let query = Arc::new(TLObject::new(query)); 
        let (mut iter, mut peer) = dht.known_peers.first();
        let (wait, mut queue_reader) = Wait::new();
        while peer.is_some() {
            while let Some(next) = peer {
                peer = dht.known_peers.next(&mut iter);
                let dht = dht.clone();  
                let query = query.clone();
                let wait = wait.clone();
                wait.request();
                tokio::spawn(
                    async move {
                        let ret = match dht.query(&next, &query).await {
                            Ok(Some(answer)) => {
                                match Query::parse::<TLObject, Stored>(answer, &query) {
                                    Ok(_) => Some(()), // Probably stored
                                    Err(answer) => {
                                        log::debug!(
                                            target: TARGET, 
                                            "Improper store reply: {:?}", 
                                            answer
                                        );
                                        None
                                    }
                                }
                            },
                            Ok(None) => None, // No reply at all 
                            Err(e) => {
                                log::warn!(target: TARGET, "Store error: {:?}", e);
                                None
                            }
                        };
                        wait.respond(ret)
                    }
                );
            }
            loop {  
                match wait.wait(&mut queue_reader, false).await { 
                    Some(_) => (),
                    None => break
                }
            }
/*            
            while let Some(next) = peer {
                let answer = dht.query(&next, &query).await?;
                if let Some(answer) = answer {
                    match Query::parse::<TLObject, Stored>(answer, &query) {
                        Ok(_) => (), // Probably stored
                        Err(answer) => log::debug!(
                            target: TARGET, 
                            "Improper store IP address reply: {:?}", 
                            answer
                        )
                    }
                } else {
                    // No reply at all
                }
                peer = dht.known_peers.next(&mut iter);
            }
*/
            let vals = DhtNode::find_value(
                dht, 
                key.clone(), 
                check_type, 
                check_all, 
                &mut None
            ).await?;
            if check_vals(vals)? {
                return Ok(true)
            }
            peer = dht.known_peers.next(&mut iter);
        }
        Ok(false)
    }

    async fn value_query(
        &self, 
        peer: &Arc<KeyId>, 
        query: &Arc<TLObject>,
        key: &Arc<KeyId>,
        check: impl Fn(&TLObject) -> bool
    ) -> Result<Option<(DhtKeyDescription, TLObject)>> {
        let answer = self.query(peer, query).await?;
        if let Some(answer) = answer {
            let answer: DhtValueResult = Query::parse(answer, &query)?;
            match answer {
                DhtValueResult::Dht_ValueFound(value) => {
                    let value = value.value.only();
                    log::debug!(
                        target: TARGET, 
                        "Found value for key {}: {:?}/{:?}", 
                        key, value.key, value.value
                    );
                    let object = deserialize(&value.value.0)?;
                    if check(&object) {
                        return Ok(Some((value.key, object)))
                    } 
                    log::debug!(
                        target: TARGET,
                        "Improper value found, object {:?}", 
                        object
                    );
                },
                DhtValueResult::Dht_ValueNotFound(nodes) => {
                    let nodes = nodes.nodes.nodes;
                    log::debug!(
                        target: TARGET, 
                        "Value not found on {} for key {}, suggested {} other nodes", 
                        peer, key, nodes.len()
                    );
                    for node in nodes.iter() {          
                        self.add_peer(node)?;
                    }
                }
            }
        } else {
            log::debug!(target: TARGET, "No answer from {} to FindValue {} query", peer, key);
        }
        Ok(None) 
    }

    fn verify_other_node(&self, node: &Node) -> Result<()> {
        let other_key = KeyOption::from_tl_public_key(&node.id)?;
        let mut node = node.clone();
        verify!(node, other_key);
        Ok(())
    }

    fn verify_value(&self, value: &DhtValue) -> Result<()> {
        let other_key = KeyOption::from_tl_public_key(&value.key.id)?;
        let mut key = value.key.clone();
        verify!(key, other_key);
        let mut value = value.clone();
        verify!(value, other_key);
        Ok(())
    }

}

#[async_trait::async_trait]
impl Subscriber for DhtNode {

    async fn try_consume_query(&self, object: TLObject) -> Result<QueryResult> {
        let object = match object.downcast::<DhtPing>() {
            Ok(query) => return QueryResult::consume(self.process_ping(&query)?),
            Err(object) => object
        };
        let object = match object.downcast::<FindNode>() {
            Ok(query) => return QueryResult::consume(self.process_find_node(&query)?),
            Err(object) => object
        };
        let object = match object.downcast::<FindValue>() {
            Ok(query) => return QueryResult::consume_boxed(self.process_find_value(&query)?),
            Err(object) => object
        };
        let object = match object.downcast::<GetSignedAddressList>() {
            Ok(_) => return QueryResult::consume_boxed(deserialize(&self.query_prefix)?),
            Err(object) => object
        };
        match object.downcast::<Store>() {
            Ok(query) => QueryResult::consume_boxed(self.process_store(query)?),
            Err(object) => {
                log::warn!(target: TARGET, "Unexpected DHT query {:?}", object);
                Ok(QueryResult::Rejected(object))
            }        
        }
    }    

    async fn try_consume_query_bundle(&self, mut objects: Vec<TLObject>) -> Result<QueryResult> {
        if objects.len() != 2 {
            return Ok(QueryResult::RejectedBundle(objects));
        }
        let other_node = match objects.remove(0).downcast::<DhtQuery>() {
            Ok(query) => query.node,
            Err(object) => {
                objects.insert(0, object); 
                return Ok(QueryResult::RejectedBundle(objects));
            }
        };  
        self.add_peer(&other_node)?;
        let ret = self.try_consume_query(objects.remove(0)).await?;
        if let QueryResult::Rejected(object) = ret {
            fail!("Unexpected DHT query {:?}", object);
        }
        Ok(ret)
    }    

}
