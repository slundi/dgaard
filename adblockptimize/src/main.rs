mod cli;
// mod io;
mod model;
// mod util;

use rayon::prelude::*;

#[tokio::main]
async fn main() {
    let opts = cli::parse();
    // process lists in parralel
    opts.paths.par_iter().for_each(|list| {

    });

    // gather result, deduplicate, sort
}
