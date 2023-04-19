use std::fs::File;
use std::io::prelude::*;
use serde::{ Deserialize };
use chrono::prelude::*;
use sitemap::writer::SiteMapWriter;
use sitemap::structs::{UrlEntry, ChangeFreq, SiteMapEntry};

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

    //  Create the sitemap.
    let mut output = Vec::<u8>::new();
    let sitemap_writer = SiteMapWriter::new(&mut output);
    let mut urlwriter = sitemap_writer.start_urlset().expect("Can't write the file");
    let date = DateTime::from_utc(NaiveDate::from_ymd(2016, 7, 8).and_hms(9, 10, 11),
                                    FixedOffset::east(0));
    let url_entry = UrlEntry::builder()
        .loc("http://www.example.com/index.html")
        .changefreq(ChangeFreq::Daily)
        .priority(0.2)
        .lastmod(date)
        .build()
        .expect("valid");
    urlwriter.url(url_entry).expect("Can't write the file");
    let date1 = DateTime::from_utc(NaiveDate::from_ymd(2016, 7, 18).and_hms(9, 10, 11),
                                    FixedOffset::east(0));
    let url_entry = UrlEntry::builder()
        .loc("http://www.example.com/other.html")
        .changefreq(ChangeFreq::Monthly)
        .priority(0.1)
        .lastmod(date1)
        .build()
        .expect("valid");
    urlwriter.url(url_entry).expect("Can't write the file");
    let sitemap_writer = urlwriter.end().expect("close the urlset block");

    //  Convert each publication.
    for article in deserialized.publications {        
        //  Convert date.
        let date = Utc.datetime_from_str(
            &(article.releaseDate + " 00:00:00"),
            "%Y-%m-%d %H:%M:%S"
        ).unwrap();  //  "2018-03-20"
        //  println!("{}", date);

        //  Set GUID to URL.
        // let mut guid = rss::Guid::default();
        // guid.set_value(article.website.clone().replace("&", "&amp;"));

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
        // let item = ItemBuilder::default()
        //     .guid(Some(guid))
        //     .title(Some(article.name))
        //     .description(Some(article.summary))
        //     .link(Some(article.website))
        //     .pub_date(Some(date.to_rfc2822()))
        //     .build()
        //     .unwrap();
        // items.push(item);
    }
    //  Compose the sitemap.
    let mut sitemap_index_writer = sitemap_writer.start_sitemapindex()
        .expect("start sitemap index tag");
    let sitemap_entry = SiteMapEntry::builder()
        .loc("http://www.example.com/other_sitemap.xml")
        .lastmod(date1)
        .build()
        .expect("valid");
    sitemap_index_writer.sitemap(sitemap_entry).expect("Can't write the file");
    sitemap_index_writer.end().expect("close sitemap block");

    //  Write the sitemap.
    let string = std::str::from_utf8(&output)
        .expect("Convert sitemap failed");
    let mut file = File::create("/tmp/sitemap.xml")
        .expect("Create sitemap.xml failed");
    file.write_all(string.as_bytes())
        .expect("Write sitemap.xml failed");
    // println!("{:?}", string);
}
