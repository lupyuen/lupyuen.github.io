use serde::{Deserialize};
use rss::ChannelBuilder;
use rss::Channel;

#[derive(Deserialize, Debug)]
struct Point {
    x: i32,
    y: i32,
}

fn main() {
    let json = std::fs::read_to_string("../resume.json").unwrap();

    // Convert the JSON string to a Point.
    let deserialized: Point = serde_json::from_str(&json).unwrap();

    // Prints deserialized = Point { x: 1, y: 2 }
    println!("deserialized = {:?}", deserialized);

    let channel = ChannelBuilder::default()
    .title("Channel Title")
    .link("http://example.com")
    .description("An RSS feed.")
    .build()
    .unwrap();
    let channel = Channel::default();
    channel.write_to(::std::io::sink()).unwrap(); // // write to the channel to a writer
    let string = channel.to_string(); // convert the channel to a string
}
