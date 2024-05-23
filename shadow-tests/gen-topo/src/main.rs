use clap::Parser;
use rand::seq::SliceRandom;

#[derive(Parser)]
struct Args {
    number: usize,
    neigh: usize,
}

fn main() {
    let args = Args::parse();
    if args.neigh >= args.number {
        panic!("a node cannot have more neighbors than there are other nodes!")
    }

    let mut nodes = Vec::new();
    let mut rng = rand::thread_rng();
    let mut ret = "adjacencies:\n".to_owned();

    for _ in 0..args.number {
        let pname = petname::petname(1, ":").unwrap();
        nodes.push(pname);
    }

    for (i, node) in nodes.iter().enumerate() {
        let mut other_nodes = nodes.clone();
        other_nodes.remove(i);
        for _ in 0..args.neigh {
            let neigh = other_nodes.choose(&mut rng).unwrap().clone();
            ret += &format!("   - [{}, {}]\n", node, neigh);
            other_nodes.retain(|x| x != &neigh);
        }
    }

    println!("{ret}")
}
