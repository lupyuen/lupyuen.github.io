use serde::{Deserialize};
use rss::ChannelBuilder;
//  use rss::Channel;

/*
"publications": [
    {
      "name": "Developing cost-effective, energy efficient IoT solutions for outdoor as well as indoor applications",
      "publisher": "OpenGov",
      "releaseDate": "2018-03-20",
      "website": "https://www.opengovasia.com/articles/developing-cost-effective-energy-efficient-iot-solutions-for-outdoor-as-well-as-indoor-applications",
      "summary": "Lup Yuen talks about two classes of IoT, ‘deep’ IoT and ‘wide’ IoT. Deep IoT devices require high bandwidth and power supply. UnaBiz looks at wide IoT, which refers to devices that are very light, battery-powered and operate on pervasive networks. They can work anytime, anywhere in Singapore and do not rely on WiFi or the cellular network."
    },  
*/

#[derive(Deserialize, Debug)]
struct Point {
    publications: [Publication; 30],
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct Publication {
    name: String,           //  "Developing cost-effective, energy efficient IoT solutions for outdoor as well as indoor applications",
    publisher: String,      //  "OpenGov",
    releaseDate: String,    // "2018-03-20",
    website: String,        // "https://www.opengovasia.com/articles/developing-cost-effective-energy-efficient-iot-solutions-for-outdoor-as-well-as-indoor-applications",
    //  summary: String,        // "Lup Yuen talks about two classes of IoT, ‘deep’ IoT and ‘wide’ IoT. Deep IoT devices require high bandwidth and power supply. UnaBiz looks at wide IoT, which refers to devices that are very light, battery-powered and operate on pervasive networks. They can work anytime, anywhere in Singapore and do not rely on WiFi or the cellular network."
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
    //  let channel = Channel::default();
    channel.write_to(::std::io::sink()).unwrap(); // // write to the channel to a writer
    //  let string = channel.to_string(); // convert the channel to a string
}
