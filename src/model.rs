use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DomainEntryFlags: u8 {
        const NONE = 0b0000_0000;
        const WHITELIST = 0b0000_0001;
        const WILDCARD = 0b0000_0010;
        const REGEX = 0b000_0100;
        const ANONYMOUS = 0b0000_1000;
        const NO_LOG = 0b0001_0000;
        /// Use for ABP lines that contains CSS or JS or any filter rule that a browser can render.
        /// It will be usefull generate a light list for web browser so the user can serve it.
        const INVALID = 0b1000_0000;
    }
}

// Compact "hot" struct: fixed size: 16 bytes, perfect for a sorted Vec or rkyv archive
pub struct DomainEntry {
    pub hash: u64,
    pub flags: DomainEntryFlags, // 1: WL, 2: Wildcard, 4: Regex, 8: Anonymous, 16: NoLog
    pub depth: u8,               // sub domain depth: 0 TLD, 1 example.com, >= 2 sub domains
    pub data_idx: u32,           // Index to the regex or pattern, 0 if none
}

// Raw domain entry used during rule parsing before creating a mapping file (so dgaard does not need to be queried for
// this) and isolating regexes
pub struct RawDomainEntry {
    pub hash: u64,
    pub value: String,           // needed
    pub flags: DomainEntryFlags, // 1: WL, 2: Wildcard, 4: Regex, 8: Anonymous, 16: NoLog
    pub depth: u8,               // sub domain depth: 0 TLD, 1 example.com, >= 2 sub domains
}
