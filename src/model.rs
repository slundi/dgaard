// Compact "hot" struct: fixed size: 16 bytes, perfect for a sorted Vec or rkyv archive
pub struct DomainEntry {
    pub hash: u64,
    pub flags: u8,     // 1: WL, 2: Wildcard, 4: Regex, 8: Anonymous, 16: NoLog
    pub depth: u8,     // sub domain depth: 0 TLD, 1 example.com, >= 2 sub domains
    pub data_idx: u32, // Index to the regex or pattern, 0 if none
}

// Raw domain entry used during rule parsing before creating a mapping file (so dgaard does not need to be queried for
// this) and isolating regexes
pub struct RawDomainEntry {
    pub hash: u64,
    pub value: String, // needed
    pub flags: u8,     // 1: WL, 2: Wildcard, 4: Regex, 8: Anonymous, 16: NoLog
    pub depth: u8,     // sub domain depth: 0 TLD, 1 example.com, >= 2 sub domains
}
