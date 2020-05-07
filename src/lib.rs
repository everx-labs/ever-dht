use adnl::{
    common::{
        deserialize, hash, KeyId, KeyOption, Query, QueryResult, serialize, 
        serialize_inplace, Subscriber, Version
    }, 
    node::{AddressCache, AdnlNode, IpAddress}
};
use overlay::OverlayShortId;
use rand::Rng;
use std::{mem, ops::Deref, sync::Arc};
use ton_api::{
    AnyBoxedSerialize, IntoBoxed, 
    ton::{
        self, TLObject, 
        adnl::AddressList, 
        dht::{
            Node as NodeBoxed, Nodes as NodesBoxed, Pong as DhtPongBoxed, Stored, UpdateRule,
            ValueResult as DhtValueResult,
            key::Key as DhtKey, keydescription::KeyDescription as DhtKeyDescription, 
            node::Node, pong::Pong as DhtPong, value::Value as DhtValue
        },
        overlay::Nodes as OverlayNodes,
        rpc::dht::{
            FindNode, FindValue, GetSignedAddressList, Ping as DhtPing, Query as DhtQuery, 
            Store
        }
    }
};
use ton_types::{fail, Result};

pub(crate) const TARGET: &str = "dht";

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

/// DHT Node
pub struct DhtNode {
    adnl: Arc<AdnlNode>,
    known_peers: AddressCache,
    node_key: Arc<KeyOption>,
    query_prefix: Vec<u8>,
}

impl DhtNode {

    const MAX_PEERS: u32 = 65536;
    const TIMEOUT_VALUE: i32 = 3600; // Seconds

    /// Constructor 
    pub fn with_adnl_node(adnl: Arc<AdnlNode>, key_tag: usize) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        let mut ret = Self {
            adnl,
            known_peers: AddressCache::with_limit(Self::MAX_PEERS),
            node_key,
            query_prefix: Vec::new()
        };
        let query = DhtQuery { 
            node: ret.sign_local_node()? 
        };
        serialize_inplace(&mut ret.query_prefix, &query)?;
        Ok(Arc::new(ret))
    }

    /// Add DHT peer 
    pub fn add_peer(
        &self, 
        peer_ip: &IpAddress, 
        peer_key: &Arc<KeyOption>
    ) -> Result<Arc<KeyId>> {
        let ret = self.adnl.add_peer(self.node_key.id(), peer_ip, peer_key)?;
        self.known_peers.put(ret.clone())?;
        Ok(ret)
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
            let node = self.verify_other_node(node.clone())?;
            self.add_peer(
                &AdnlNode::parse_address_list(&node.addr_list)?,
                &Arc::new(KeyOption::from_tl_public_key(&node.id)?)
            )?;
        }
        Ok(true)
    }

    /// Find IP address of node with given key ID 
    pub async fn find_ip_address(&self, key_id: &Arc<KeyId>) -> Result<IpAddress> {
        let mut addr_list = None;
        self.find_value(
            Self::dht_key_from_key_id(key_id, "address"),
            |update: AddressList| {
                addr_list.replace(update.only());
                Ok(true)
            }
        ).await?;
        if let Some(addr_list) = addr_list {
            AdnlNode::parse_address_list(&addr_list)
        } else {
            fail!("No address found for {}", key_id)
        }
    }

    /// Get nodes of overlay with given ID
    pub async fn find_overlay_nodes(
        &self, 
        overlay_id: &Arc<OverlayShortId>
    ) -> Result<Vec<(IpAddress, Arc<KeyOption>)>> {
        let nodes = lockfree::map::Map::new();
        self.find_value(
            Self::dht_key_from_key_id(overlay_id, "nodes"),
            |update: OverlayNodes| {
                log::debug!(target: TARGET, "-------- Found Overlay node keys:");
                for node in update.nodes().deref() {
                    let peer = KeyOption::from_tl_public_key(&node.id)?;
                    log::debug!(target: TARGET, "{} {:?}", peer.id(), peer);
                    nodes.insert(peer.id().clone(), Arc::new(peer));
                }
                Ok(true)
            }
        ).await?;
        let mut vec = Vec::new();
        for node in nodes.iter() {
            if let Ok(addr) = self.find_ip_address(node.key()).await {
                log::debug!(
                    target: TARGET, 
                    "-------- Got Overlay node {} IP: {}", 
                    node.key(),
                    addr
                );
                vec.push((addr, node.val().clone()));
            }
        }
        Ok(vec)
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
        let _node = self.verify_other_node(answer.only())?;
        Ok(true)
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
    pub async fn store_ip_address(&self) -> Result<bool> {
        log::debug!(target: TARGET, "Storing key ID {}", self.node_key.id());
        let value = serialize(&self.adnl.build_address_list(0)?.into_boxed())?;
        let query = Store {
            value: self.sign_value("address", &value[..])?
        };
        let query = TLObject::new(query); 
        let (mut iter, mut peer) = self.known_peers.first();
        while peer.is_some() {
            while let Some(next) = peer {
                let answer = self.query(&next, &query).await?;
                if let Some(answer) = answer {
                    match Query::parse::<TLObject, Stored>(answer, &query) {
                        Ok(_) => (), // Probably stored
                        Err(answer) => println!("Improper store reply: {:?}", answer)
                    }
                } else {
                    // No reply at all
                }
                peer = self.known_peers.next(&mut iter);
            }
            if let Ok(ip) = self.find_ip_address(self.node_key.id()).await {
                if &ip == self.adnl.ip_address() {
                    log::debug!(target: TARGET, "Checked stored address {:?}", ip);
                    return Ok(true)
                }
            }
            peer = self.known_peers.next(&mut iter);
        }
        Ok(false)
    }

    fn dht_key_from_key_id(id: &Arc<KeyId>, name: &str) -> DhtKey {
        DhtKey {
            id: ton::int256(id.data().clone()),
            idx: 0,
            name: ton::bytes(name.as_bytes().to_vec())
        }
    }

    async fn find_value<I, F>(&self, key: DhtKey, mut collector: F) -> Result<bool> 
    where 
        I: AnyBoxedSerialize + Default,
        F: FnMut(I) -> Result<bool> 
    {
        let key = ton::int256(hash(key)?);
        log::debug!(target: TARGET, "FindValue {} query", key);
        let k = 6;
        let query = TLObject::new(FindValue { key, k });
        let mut found = false;
        let (mut iter, mut current) = self.known_peers.first();
        while let Some(peer) = current {
            let answer = self.query(&peer, &query).await?;
            if let Some(answer) = answer {
                let answer: DhtValueResult = Query::parse(answer, &query)?;
                if let Some(value) = answer.value() {
                    log::debug!("Found value with key {:?}", value.key());
                    let object = deserialize(&value.value().0)?;
                    match object.downcast::<I>() {
                        Ok(object) => {
                            found = true;
                            if collector(object)? {
                                return Ok(found)
                            } 
                        },
                        Err(object) => {
                            log::debug!(
                                target: TARGET,
                                "Improper value {:?} found in object {:?}", 
                                hex::encode(&value.value().0),
                                object
                            );
                        }
                    };                 	
                } else if let Some(nodes) = answer.nodes() {
                    log::debug!(
                        target: TARGET, 
                        "Value not found for key {}, suggested {} other nodes", 
                        key,
                        nodes.nodes.len()
                    );
                    for node in nodes.nodes.iter() {          
                        let key = KeyOption::from_tl_public_key(&node.id)?;
                        if self.known_peers.contains(key.id()) {
                            continue
                        }
                        self.add_peer(
                            &AdnlNode::parse_address_list(&node.addr_list)?,
                            &Arc::new(key)
                        )?;
                    }
                }
            } else {
                log::debug!(target: TARGET, "No answer from {} to FindValue {} query", peer, key);
            }
            current = self.known_peers.next(&mut iter);
        }
        Ok(found)
    }

    fn process_ping(&self, query: &DhtPing) -> Result<DhtPong> {
        Ok(DhtPong { random_id: query.random_id })
    }

    async fn query(&self, dst: &Arc<KeyId>, query: &TLObject) -> Result<Option<TLObject>> {
        self.adnl.query(dst, self.node_key.id(), query).await
    } 

    async fn query_with_prefix(
        &self, 
        dst: &Arc<KeyId>, 
        query: &TLObject
    ) -> Result<Option<TLObject>> {
        self.adnl.query_with_prefix(
            dst, 
            self.node_key.id(),
            Some(&self.query_prefix[..]), 
            query
        ).await
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
        let node = Node {
            id: self.node_key.into_tl_public_key()?,
            addr_list: self.adnl.build_address_list(0)?,
            signature: ton::bytes::default(),
            version: Version::get()
        };
        Ok(sign!(node, self.node_key))
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

    fn verify_other_node(&self, mut node: Node) -> Result<Node> {
        let other_key = KeyOption::from_tl_public_key(&node.id)?;
        Ok(verify!(node, other_key))
    }

}

impl Subscriber for DhtNode {

    fn try_consume_query(&self, object: TLObject) -> Result<QueryResult> {
println!("DHT QUERY");
        let object = match object.downcast::<DhtPing>() {
            Ok(query) => return QueryResult::consume(self.process_ping(&query)?),
            Err(object) => object
        };
        Ok(QueryResult::Rejected(object))
    }    

    fn try_consume_query_bundle(&self, mut objects: Vec<TLObject>) -> Result<QueryResult> {
println!("DHT QUERY BUNDLE");
        if objects.len() != 2 {
            return Ok(QueryResult::RejectedBundle(objects));
        }
        let object = objects.remove(0);
        let _other_node = match object.downcast::<DhtQuery>() {
            Ok(query) => self.verify_other_node(query.node)?,
            Err(object) => {
                objects.insert(0, object); 
                return Ok(QueryResult::RejectedBundle(objects));
            }
        };
        let object = objects.remove(0);
        match object.downcast::<GetSignedAddressList>() {
            Ok(_query) => Ok(QueryResult::Consumed(Some(deserialize(&self.query_prefix)?))),
            Err(object) => fail!("Unexpected DHT query {:?}", object)
        }
    }    

}


