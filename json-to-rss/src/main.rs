use serde::{ Deserialize };
use rss::{ ChannelBuilder, ItemBuilder };

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
struct Resume {
    publications: Vec<Publication>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct Publication {
    name: String,           //  "Developing cost-effective, energy efficient IoT solutions for outdoor as well as indoor applications",
    publisher: String,      //  "OpenGov",
    releaseDate: String,    // "2018-03-20",
    website: String,        // "https://www.opengovasia.com/articles/developing-cost-effective-energy-efficient-iot-solutions-for-outdoor-as-well-as-indoor-applications",
    #[serde(default)]
    summary: String,        // "Lup Yuen talks about two classes of IoT, ‘deep’ IoT and ‘wide’ IoT. Deep IoT devices require high bandwidth and power supply. UnaBiz looks at wide IoT, which refers to devices that are very light, battery-powered and operate on pervasive networks. They can work anytime, anywhere in Singapore and do not rely on WiFi or the cellular network."
}

fn main() {
    let json = std::fs::read_to_string("../resume.json").unwrap();

    // Convert the JSON string to a Point.
    let deserialized: Resume = serde_json::from_str(&json).unwrap();

    // Prints deserialized = Point { x: 1, y: 2 }
    //  println!("deserialized = {:?}", deserialized);

    let mut items = Vec::new();

    /*
    <item>
    <title>Example entry</title>
    <description>Here is some text containing an interesting description.</description>
    <link>http://www.example.com/blog/post/1</link>
    <guid isPermaLink="false">7bd204c6-1655-4c27-aeee-53f933c5395f</guid>
    <pubDate>Sun, 06 Sep 2009 16:20:00 +0000</pubDate>
    </item>
    */
    let item = ItemBuilder::default()
        .title(Some("aaa".to_string()))
        .description(Some("bbb".to_string()))
        .link(Some("ccc".to_string()))
        .pub_date(Some("ddd".to_string()))
        .build()
        .unwrap();
    items.push(item);

    let channel = ChannelBuilder::default()
        .title("lupyuen")
        .link("https://lupyuen.github.io")
        .description("IoT Techie and Educator")
        .items(items)
        .build()
        .unwrap();

    let string = channel.to_string(); // convert the channel to a string
    println!("{:?}", string);

    //  let channel = Channel::default();
    //  channel.write_to(::std::io::sink()).unwrap(); // // write to the channel to a writer
}
