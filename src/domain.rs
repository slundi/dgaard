use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize, Debug)]
pub struct DomainMap {
    // A simple list of pairs, or a hash-map compatible structure
    pub pairs: Vec<(u64, String)>,
}
