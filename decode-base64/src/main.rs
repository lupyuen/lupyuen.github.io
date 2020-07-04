fn main() {
    let lines = std::fs::read_to_string("../../Downloads/20200704.txt").unwrap(); 
    for line in lines.split("\n") {
        //  line contains b20200704-125008.txt:        Value         7b226964223a2... | "{\"id\":\"nRZAdXp...Tg==\",\"mp\":\"SM-G970F\",\"o\":\"SG_MOH\",\"v\":2}"
        //  println!("line = {:?}", line);
        if line.len() == 0 { continue; }
        let datetime = line
            .split(".")
            .collect::<Vec<&str>>()
            [0]
            .replace("b", "");
        let encoded = line
            .split("==")
            .collect::<Vec<&str>>()
            [0]
            .to_string()
            + "==";
        let encoded = encoded
            .split("|")
            .collect::<Vec<&str>>()
            [1];
        let encoded = encoded
            .split(":")
            .collect::<Vec<&str>>()
            [1]
            .replace("\\\"", "");
        let decoded = base64::decode(encoded.clone());
        //  println!("datetime = {:?}", datetime);            
        //  println!("encoded = {:?}", encoded);            
        //  println!("decoded = {:?}", decoded);           
        println!("{:?},{:?}", datetime, decoded);
    }
   
    /*
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

        /*
        <item>
        <title>Example entry</title>
        <description>Here is some text containing an interesting description.</description>
        <link>http://www.example.com/blog/post/1</link>
        <guid isPermaLink="false">7bd204c6-1655-4c27-aeee-53f933c5395f</guid>
        <pubDate>Sun, 06 Sep 2009 16:20:00 +0000</pubDate>
        </item>
        */
        //  Compose the item.
        let item = ItemBuilder::default()
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
    */
}
