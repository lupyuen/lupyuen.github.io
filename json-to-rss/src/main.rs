use serde::{Serialize, Deserialize};
use rss::ChannelBuilder;
use rss::Channel;

#[derive(Serialize, Deserialize, Debug)]
struct Point {
    x: i32,
    y: i32,
}

fn main() {
    let point = Point { x: 1, y: 2 };

    // Convert the Point to a JSON string.
    let serialized = serde_json::to_string(&point).unwrap();

    // Prints serialized = {"x":1,"y":2}
    println!("serialized = {}", serialized);

    // Convert the JSON string back to a Point.
    let deserialized: Point = serde_json::from_str(&serialized).unwrap();

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
