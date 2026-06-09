/// Print only in debug mode. Release will have print code removed.
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        println!($($arg)*);
    };
}

pub(crate) use debug_print;
