use serde::{ Deserialize };
use rss::{ ChannelBuilder, ItemBuilder };
use chrono::prelude::*;

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
    releaseDate: String,    //  "2018-03-20",
    website: String,        //  "https://www.opengovasia.com/articles/developing-cost-effective-energy-efficient-iot-solutions-for-outdoor-as-well-as-indoor-applications",
    #[serde(default)]
    summary: String,        //  "Lup Yuen talks about two classes of IoT, ‘deep’ IoT and ‘wide’ IoT. Deep IoT devices require high bandwidth and power supply. UnaBiz looks at wide IoT, which refers to devices that are very light, battery-powered and operate on pervasive networks. They can work anytime, anywhere in Singapore and do not rely on WiFi or the cellular network."
}

fn main() {
    //  Load the JSON Resume.
    let json = std::fs::read_to_string("../resume.json").unwrap();
    let deserialized: Resume = serde_json::from_str(&json).unwrap();
    //  println!("deserialized = {:?}", deserialized);

    //  Convert each publication.
    let mut items = Vec::new();
    for article in deserialized.publications {        
        //  Convert date.
        let date = Utc.datetime_from_str(
            &(article.releaseDate + " 00:00:00"),
            "%Y-%m-%d %H:%M:%S"
        ).unwrap();  //  "2018-03-20"
        //  println!("{}", date);

        //  Set GUID to URL.
        let mut guid = rss::Guid::default();
        guid.set_value(article.website.clone().replace("&", "&amp;"));

        /*
        <item>
        <guid>http://www.example.com/blog/post/1</guid>
        <title>Example entry</title>
        <description>Here is some text containing an interesting description.</description>
        <link>http://www.example.com/blog/post/1</link>
        <guid isPermaLink="false">7bd204c6-1655-4c27-aeee-53f933c5395f</guid>
        <pubDate>Sun, 06 Sep 2009 16:20:00 +0000</pubDate>
        </item>
        */
        //  Compose the item.
        let item = ItemBuilder::default()
            .guid(Some(guid))
            .title(Some(article.name))
            .description(Some(article.summary))
            .link(Some(article.website))
            .pub_date(Some(date.to_rfc2822()))
            .build()
            .unwrap();
        items.push(item);
    }
    //  Compose the channel.
    let channel = ChannelBuilder::default()
        .title("lupyuen")
        .link("https://lupyuen.github.io")
        .description("IoT Techie and Educator")
        .items(items)
        .build()
        .unwrap();

    //  Write the channel.
    let string = channel.to_string(); // convert the channel to a string
    println!("{}", string);
}
