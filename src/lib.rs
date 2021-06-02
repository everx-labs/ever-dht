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
use std::{fmt::{self, Display, Formatter}, mem, ops::Deref, sync::Arc};
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
            data.signature.0 = buf;
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

pub struct DhtIterator {
    iter: Option<AddressCacheIterator>, 
    key_id: DhtKeyId,
    order: Vec<(u8, Arc<KeyId>)>
}

impl DhtIterator {

    fn with_key_id(dht: &DhtNode, key_id: DhtKeyId) -> Self {
        let mut ret = Self {
            iter: None,
            key_id, 
            order: Vec::new() 
        };
        ret.update(dht);
        ret
    }

    fn update(&mut self, dht: &DhtNode) {
        let mut next = if let Some(iter) = &self.iter {
            dht.known_peers.given(iter)
        } else {
            dht.get_known_peer(&mut self.iter)
        };
        loop {
            if let Some(peer) = next {
                let affinity = DhtNode::get_affinity(peer.data(), &self.key_id);
                let add = if let Some((top_affinity, _)) = self.order.last() {
                    (*top_affinity <= affinity) || (self.order.len() < DhtNode::MAX_TASKS) 
                } else {
                    true
                };
                if add {
                    self.order.push((affinity, peer))
                }
                next = dht.get_known_peer(&mut self.iter)
            } else {
                break
            }
        }
        self.order.sort_unstable_by_key(|(affinity, _)| *affinity);
        if let Some((top_affinity, _)) = self.order.last() {
            let mut drop_to = 0;
            while self.order.len() - drop_to > DhtNode::MAX_TASKS {
                let (affinity, _) = self.order[drop_to];
                if affinity < *top_affinity {
                    drop_to += 1
                } else {
                    break
                }
            }
            self.order.drain(0..drop_to);
        }
        if log::log_enabled!(log::Level::Debug) {
            let mut out = format!("DHT search list for {}:\n", base64::encode(&self.key_id));
            for (affinity, key_id) in self.order.iter().rev() {
                out.push_str(format!("order {} - {}\n", affinity, key_id).as_str())
            }
            log::debug!(target: TARGET, "{}", out);
        }
    }

}

impl Display for DhtIterator {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Some(iter) = &self.iter {
            write!(f, "{} peers remained of {:?}", self.order.len(), iter)
        } else {
            write!(f, "no peers yet")
        }
    }
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
            let affinity = Self::get_affinity(key1, key2);
            add_object_to_map(
                &self.buckets, 
                affinity, 
                || Ok(lockfree::map::Map::new())
            )?;
            if let Some(bucket) = self.buckets.get(&affinity) {
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

    /// Fetch address of node (locally) with given key ID 
    pub async fn fetch_address(
        &self,
        key_id: &Arc<KeyId>
    ) -> Result<Option<(IpAddress, KeyOption)>> {
        let key = Self::dht_key_from_key_id(key_id, "address");
        let value = self.search_dht_key(&hash(key)?);
        if let Some(value) = value {
            let object = deserialize(&value.value.0)?;
            Ok(Some(Self::parse_value_as_address(value.key, object)?))
        } else {
            Ok(None)
        }
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
            Self::parse_value_as_address(key, addr_list) 
        } else {
            fail!("No address found for {}", key_id)
        }
    }

    /// Get nodes of overlay with given ID
    pub async fn find_overlay_nodes(
        dht: &Arc<Self>, 
        overlay_id: &Arc<OverlayShortId>,
        iter: &mut Option<DhtIterator>
    ) -> Result<Vec<(IpAddress, OverlayNode)>> {
        let mut ret = Vec::new();
        let mut nodes = Vec::new();
        log::trace!(
            target: TARGET, 
            "-------- Overlay nodes search, {}", 
            if let Some(iter) = iter {
                iter.to_string()
            } else {
                format!("{} peers remained", dht.known_peers.count())
            }
        );
        loop {
            let mut nodes_lists = DhtNode::find_value(
                dht, 
                Self::dht_key_from_key_id(overlay_id, "nodes"),
                |object| object.is::<OverlayNodesBoxed>(),
                true, 
                iter
            ).await?;
            if nodes_lists.is_empty() {
                // No more results
                break
            }
            while let Some((_, nodes_list)) = nodes_lists.pop() {
                if let Ok(nodes_list) = nodes_list.downcast::<OverlayNodesBoxed>() {
                    nodes.append(&mut nodes_list.only().nodes.0)
                } else {
                    fail!("INTERNAL ERROR: overlay nodes list type mismatch in search")
                } 
            }
            let (wait, mut queue_reader) = Wait::new();
            let cache = AddressCache::with_limit(Self::MAX_PEERS);
            log::debug!(
                target: TARGET, 
                "-------- Searching {} overlay nodes", 
                nodes.len()
            );
            while let Some(node) = nodes.pop() {
                let node = node.clone();
                let key = KeyOption::from_tl_public_key(&node.id)?;
                if !cache.put(key.id().clone())? {
                    log::trace!(
                        target: TARGET, 
                        "-------- Overlay node {} already found", 
                        key.id()
                    );
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
                                "-------- Got Overlay node {} IP: {}, key: {}", 
                                key.id(), ip, 
                                base64::encode(key.pub_key().unwrap_or(&[0u8; 32]))
                            );
                            wait.respond(Some((Some(ip), node)))
                        } else {
                            log::trace!(
                                target: TARGET, 
                                "-------- Overlay node {} not found", 
                                key.id()
                            );
                            wait.respond(Some((None, node))) 
                        }
                    }
                );
            }
            loop {  
                match wait.wait(&mut queue_reader, false).await { 
                    Some(Some((None, node))) => nodes.push(node),
                    Some(Some((Some(ip), node))) => ret.push((ip, node)),
                    _ => break
                }
            }
            if !ret.is_empty() {
                // Found some
                break
            }
            if iter.is_none() {
                // Search is over
                break
            }
        }
        log::trace!(
            target: TARGET, 
            "-------- Overlay nodes to return: {}", 
            ret.len()
        );
        Ok(ret)
    }

    /// Get DHT peer via iterator
    pub fn get_known_peer(&self, iter: &mut Option<AddressCacheIterator>) -> Option<Arc<KeyId>> {
        if let Some(iter) = iter {
            self.known_peers.next(iter)
        } else {
            let (new_iter, first) = self.known_peers.first();
            iter.replace(new_iter);
            first
        }
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
    pub async fn store_ip_address(dht: &Arc<Self>, key: &Arc<KeyOption>) -> Result<bool> {
        log::debug!(target: TARGET, "Storing key ID {}", key.id());
        let value = serialize(&dht.adnl.build_address_list(None)?.into_boxed())?;
        let value = Self::sign_value("address", &value[..], key)?;
        let key = Self::dht_key_from_key_id(key.id(), "address");
        dht.process_store_signed_value(hash(key.clone())?, value.clone())?;
        Self::store_value(
            dht,
            key,
            value,
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
        dht.process_store_overlay_nodes(hash(key.clone())?, value.clone())?;
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
        iter_opt: &mut Option<DhtIterator>
    ) -> Result<Vec<(DhtKeyDescription, TLObject)>> {
        let key = hash(key)?;
        let iter = iter_opt.get_or_insert_with(||DhtIterator::with_key_id(dht, key.clone()));
        if iter.key_id != key {
            fail!("INTERNAL ERROR: DHT key mismatch in value search")
        }
        let mut ret = Vec::new();
        let query = TLObject::new(
            FindValue { 
                key: ton::int256(key.clone()),
                k: 6 
            }
        );
        let key = Arc::new(key); 
        let query = Arc::new(query);
        let (wait, mut queue_reader) = Wait::new();  
        let mut known_peers = dht.known_peers.count();
        log::debug!(
            target: TARGET, 
            "FindValue with DHT key ID {} query, {}", 
            base64::encode(&key[..]), iter
        );
        loop {
            while let Some((_, peer)) = iter.order.pop() {
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
                if reqs >= Self::MAX_TASKS {
                    break;
                } 
            } 
            log::debug!(
                target: TARGET, 
                "FindValue with DHT key ID {} query, {} parallel reqs, {}", 
                base64::encode(&key[..]), wait.count(), iter
            );
            let mut finished = false; 
            loop {
                match wait.wait(&mut queue_reader, !all).await { 
                    Some(None) => (),
                    Some(Some(val)) => ret.push(val),
                    None => finished = true
                }
                // Update iterator if required
                if all || ret.is_empty() {
                    let updated_known_peers = dht.known_peers.count();
                    if updated_known_peers != known_peers {
                        iter.update(dht);
                        known_peers = updated_known_peers;
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
        }
        if iter.order.is_empty() {
            iter_opt.take();
        }
        Ok(ret)
    }

    fn get_affinity(key1: &DhtKeyId, key2: &DhtKeyId) -> u8 {
        let mut ret = 0;
        for i in 0..32 {
            match key1[i] ^ key2[i] {
                0 => ret += 8,
                x => {
                    if (x & 0xF0) == 0 {
                        ret += Self::BITS[(x & 0x0F) as usize] + 4
                    } else {
                        ret += Self::BITS[(x >> 4) as usize]
                    }
                    break
                }
            }
        }
        ret
    }

    fn parse_value_as_address(
        key: DhtKeyDescription, 
        value: TLObject
    ) -> Result<(IpAddress, KeyOption)> {
        if let Ok(addr_list) = value.downcast::<AddressListBoxed>() {
            let ip_address = AdnlNode::parse_address_list(&addr_list.only())?;
            let key = KeyOption::from_tl_public_key(&key.id)?;
            Ok((ip_address, key))
        } else {
            fail!("Address list type mismatch in DHT search")
        }
    }

    fn process_find_node(&self, query: &FindNode) -> Result<Nodes> {
        log::trace!(target: TARGET, "Process FindNode query {:?}", query);
        let key1 = self.node_key.id().data();
        let key2 = get256(&query.key);
        let mut dist = 0u8;
        let mut ret = Vec::new();
        for i in 0..32 {
            if ret.len() == query.k as usize {
                break;
            }
            let mut subdist = dist;
            let mut xor = key1[i] ^ key2[i];
            while xor != 0 {
                if (xor & 0xF0) == 0 {
                    subdist = subdist.saturating_add(4);
                    xor <<= 4;
                } else {
                    let shift = Self::BITS[(xor >> 4) as usize];
                    subdist = subdist.saturating_add(shift);
                    if let Some(bucket) = self.buckets.get(&subdist) {
                        for node in bucket.val().iter() {         
                            ret.push(node.val().clone());
                            if ret.len() == query.k as usize {
                                break
                            }
                        }
                    }
                    xor <<= shift + 1;
                    subdist = subdist.saturating_add(1);
                }
                if ret.len() == query.k as usize {
                    break
                }
            }
            dist = dist.saturating_add(8);
        }
        let ret = Nodes {
            nodes: ret.into()
        };
        log::trace!(target: TARGET, "FindNode result {:?}", ret);
        Ok(ret)
    }

    fn process_find_value(&self, query: &FindValue) -> Result<DhtValueResult> {
        log::trace!(target: TARGET, "Process FindValue query {:?}", query);
        let ret = if let Some(value) = self.search_dht_key(get256(&query.key)) {
            ValueFound {
                value: value.into_boxed()
            }.into_boxed()
        } else {
            ValueNotFound {
                nodes: Nodes {
                    nodes: self.get_known_nodes(query.k as usize)?.into()
                }
            }.into_boxed()
        };
        log::trace!(target: TARGET, "FindValue result {:?}", ret);
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
        log::trace!(target: TARGET, "Process Store Overlay Nodes {:?}", value);
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
                    } else if old_value.ttl > value.ttl {
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
                        if node.id == old_node.id {
                            if node.version > old_node.version {
                                *old_node = node.clone()
                            } else {
                                return Ok(None)
                            }
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
                log::trace!(target: TARGET, "Store Overlay Nodes result {:?}", ret);
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
        self.adnl.clone().query(query, &peers, None).await
    } 

    async fn query_with_prefix(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TLObject
    ) -> Result<Option<TLObject>> {
        let peers = AdnlPeers::with_keys(self.node_key.id().clone(), dst.clone());
        self.adnl.clone()
            .query_with_prefix(Some(&self.query_prefix[..]), query, &peers, None)
            .await
    } 

   fn search_dht_key(&self, key: &DhtKeyId) -> Option<DhtValue> { 
        let version = Version::get();
        if let Some(value) = self.storage.get(key) {
            if value.val().ttl > version {
                Some(value.val().clone())
            } else {
                None
            }
        } else {
            None
        }
    }
    
    fn sign_key_description(name: &str, key: &Arc<KeyOption>) -> Result<DhtKeyDescription> {
        let key_description = DhtKeyDescription {
            id: key.into_tl_public_key()?,
            key: Self::dht_key_from_key_id(key.id(), name),
            signature: ton::bytes::default(),
            update_rule: UpdateRule::Dht_UpdateRule_Signature
        };
        Ok(sign!(key_description, key))
    }    

    fn sign_local_node(&self) -> Result<Node> {
        let local_node = Node {
            id: self.node_key.into_tl_public_key()?,
            addr_list: self.adnl.build_address_list(None)?,
            signature: ton::bytes::default(),
            version: Version::get()
        };
        Ok(sign!(local_node, self.node_key))
    }

    fn sign_value(name: &str, value: &[u8], key: &Arc<KeyOption>) -> Result<DhtValue> {
        let value = DhtValue {
            key: Self::sign_key_description(name, key)?,
            ttl: Version::get() + Self::TIMEOUT_VALUE,
            signature: ton::bytes::default(),
            value: ton::bytes(value.to_vec())
        };
        Ok(sign!(value, key))
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
        key: &Arc<DhtKeyId>,
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
                        "Found value for DHT key ID {}: {:?}/{:?}", 
                        base64::encode(&key[..]), value.key, value.value
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
                        "Value not found on {} for DHT key ID {}, suggested {} other nodes",
                        peer, base64::encode(&key[..]), nodes.len()
                    );
                    for node in nodes.iter() {          
                        self.add_peer(node)?;
                    }
                }
            }
        } else {
            log::debug!(
                target: TARGET, 
                "No answer from {} to FindValue with DHT key ID {} query", 
                peer, base64::encode(&key[..])
            );
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

    async fn try_consume_query(
        &self, 
        object: TLObject, 
        _peers: &AdnlPeers
    ) -> Result<QueryResult> {
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
            Ok(_) => return QueryResult::consume(self.get_signed_node()?),
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

    async fn try_consume_query_bundle(
        &self, 
        mut objects: Vec<TLObject>,
        peers: &AdnlPeers
    ) -> Result<QueryResult> {
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
        let ret = self.try_consume_query(objects.remove(0), peers).await?;
        if let QueryResult::Rejected(object) = ret {
            fail!("Unexpected DHT query {:?}", object);
        }
        Ok(ret)
    }    

}
