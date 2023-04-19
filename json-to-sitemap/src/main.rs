use std::fs::File;
use std::io::prelude::*;
use serde::{ Deserialize };
use chrono::prelude::*;
use sitemap::writer::SiteMapWriter;
use sitemap::structs::{UrlEntry};

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

#[derive(Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
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

    //  Create the sitemap.
    let mut output = Vec::<u8>::new();
    let sitemap_writer = SiteMapWriter::new(&mut output);
    let mut urlwriter = sitemap_writer.start_urlset().expect("Can't write the file");

    //  Add our home page based on the first date.
    let article = deserialized.publications[0].clone();
    let date = Utc.datetime_from_str(
        &(article.releaseDate + " 00:00:00"),
        "%Y-%m-%d %H:%M:%S"
    ).unwrap();  //  "2018-03-20"
    let url_entry = UrlEntry::builder()
        .loc("https://lupyuen.github.io/")
        .lastmod(date.into())
        .build()
        .expect("valid");
    urlwriter.url(url_entry).expect("Can't write the file");

    //  Convert each publication.
    for article in deserialized.publications {        
        //  Convert date.
        let date = Utc.datetime_from_str(
            &(article.releaseDate + " 00:00:00"),
            "%Y-%m-%d %H:%M:%S"
        ).unwrap();  //  "2018-03-20"
        //  println!("{}", date);

        //  Skip non-articles.
        if !article.website.starts_with("https://lupyuen.github.io/articles/") { continue; }

        //  Compose the item.
        let url_entry = UrlEntry::builder()
            .loc(article.website)
            .lastmod(date.into())
            .build()
            .expect("valid");
        urlwriter.url(url_entry).expect("Can't write the file");
        /*
        <url>
            <loc>https://lupyuen.github.io/articles/lte</loc>
            <lastmod>2023-04-12T00:00:00+00:00</lastmod>
        </url>
        */
    }
    //  Compose the sitemap.
    let string = std::str::from_utf8(&output)
        .expect("Convert sitemap failed");
    // println!("{:?}", string);

    //  Write the sitemap.
    let mut file = File::create("../sitemap.xml")
        .expect("Create sitemap.xml failed");
    file.write_all(string.as_bytes())
        .expect("Write sitemap.xml failed");
}
