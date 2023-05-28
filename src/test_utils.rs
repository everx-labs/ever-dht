/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

pub struct OtherNode {
    key: String,
    ip: String,
    signature: String,
    timestamp: Option<i32>
}

pub fn extract_other_nodes(config: &str) -> Vec<OtherNode> {

    const MASK_READ_KEY: u16 = 0x0001;
    const MASK_READ_IP: u16 = 0x0002;
    const MASK_READ_PORT: u16 = 0x0004;

    let mut ret = Vec::new();
    let file = File::open(config).expect("Config file not found");
    let buf_reader = BufReader::new(file);
    
    let mut key: Option<String> = None;
    let mut ip: Option<String> = None;
    let mut mask = 0;
    let mut timestamp = None;

    for line in buf_reader.lines() {
        let line = line.unwrap();
        let line = line.trim();
        if line.strip_prefix("\"@type\": \"pub.ed25519\"").is_some() {
            mask |= MASK_READ_KEY;
            key = None;
            ip = None;
            continue;
        }
        if line.strip_prefix("\"@type\": \"adnl.address.udp\"").is_some() {
            mask |= MASK_READ_IP;                                 
            continue;
        }
        if let Some(line) = line.strip_prefix("\"version\": ") {
            if let Some(line) = line.strip_suffix(",") {
                match line.parse::<i32>().expect("Timestamp") {
                    0 | -1 => (),
                    version => timestamp = Some(version)
                }
            }
            continue;
        }
        if let Some(line) = line.strip_prefix("\"signature\": \"") {
            if let Some(signature) = line.strip_suffix("\"") {
                if let Some(key) = key.as_ref() {
                    if let Some(ip) = ip.as_ref() {
                        let node = OtherNode {
                            key: key.to_string(), 
                            ip: ip.to_string(), 
                            signature: signature.to_string(),
                            timestamp
                        };
                        ret.push(node)
                    }
                }
            }
            continue;
        }
        if (mask & MASK_READ_KEY) != 0 {
            mask &= !MASK_READ_KEY;
            if line.starts_with("\"key\": \"") && line.ends_with("\"") {
                key = Some(line.get(8..line.len() - 1).expect("Key").to_string()); 
            }
            continue;
        }
        if (mask & MASK_READ_IP) != 0 {
            mask &= !MASK_READ_IP;
            mask |= MASK_READ_PORT;
            if line.starts_with("\"ip\": ") && line.ends_with(",") {
                let ip_dec: i32 = line.get(6..line.len() - 1).expect("IP").parse().expect("IP");
                let ip_hex: u32 = ip_dec as u32;
                ip = Some(
                    format!(
                        "{}.{}.{}.{}", 
                        (ip_hex >> 24) & 0xFF, (ip_hex >> 16) & 0xFF, 
                        (ip_hex >>  8) & 0xFF, (ip_hex >>  0) & 0xFF
                    )
                ); 
            }
            continue;
        }
        if (mask & MASK_READ_PORT) != 0 {
            mask &= !MASK_READ_PORT;
            if line.starts_with("\"port\": ") {
                let port: u16 = line.get(8..).expect("Port").parse().expect("Port");
                ip = Some(format!("{}:{}", ip.unwrap(), port));
            }
            continue;
        }
    }
    ret 

}

async fn try_other_node(dht: &Arc<DhtNode>, node: &OtherNode) -> Result<Arc<KeyId>> {
    println!("\nTrying DHT peer {}", node.ip.as_str());
    let peer = dht.add_peer(
        &build_dht_node_info_with_timestamp(
            node.ip.as_str(), 
            node.key.as_str(), 
            node.signature.as_str(),
            node.timestamp
        )?
    )?.ok_or_else(
        || error!("Cannot add DHT peer {}", node.ip) 
    )?;
    println!("\nDHT peer {} added", node.ip.as_str());
    if !dht.ping(&peer).await? {
        fail!("Cannot ping DHT peer {}", node.ip) 
    }       	
    Ok(peer)
}

pub async fn select_other_node(dht: &Arc<DhtNode>, other_nodes: &Vec<OtherNode>) -> Arc<KeyId> {
    for other_node in other_nodes.iter() {
        match try_other_node(&dht, other_node).await {
            Ok(peer) => return peer,
            Err(e) => println!("{}", e)
        }
    }
    panic!("Cannot select peer for test")
}
