fn main() {
    let lines = std::fs::read_to_string("../../Downloads/20200705.txt").unwrap(); 
    let mut mac = Vec::new();
    let mut manu = Vec::new();
    for line in lines.split("\n") {
        //  line contains b20200704-125008.txt:        Value         7b226964223a2... | "{\"id\":\"nRZAdXp...Tg==\",\"mp\":\"SM-G970F\",\"o\":\"SG_MOH\",\"v\":2}"
        if line.len() == 0 || !line.contains(":") { continue; }
            
        let datetime = line
            .split(".")
            .collect::<Vec<&str>>()
            [0]
            .replace("b", "");
        //  println!("datetime = {:?}", datetime);            
        let line = 
            line
            .splitn(2, ":")
            .collect::<Vec<&str>>()
            [1];
        if line.starts_with("Scan")
            || line.starts_with("Connect")
            { continue; }

        //  line contains Value 7b226964223a2... | "{\"id\":\"nRZAdXp...Tg==\",\"mp\":\"SM-G970F\",\"o\":\"SG_MOH\",\"v\":2}"
        //  or Value 28dc2dfb72... | \"(\\xdc-\\xfb...\\xe8\"
        //  or [49:b7:00:00:00:00] RSSI -96:
        //  or Manu: FF03393161
        //  println!("line = {:?}", line);
        if line.starts_with("[") {
            //  line contains [49:b7:00:00:00:00] RSSI -96:
            let encoded = line
                .split(" ")
                .collect::<Vec<&str>>()
                [0]
                .replace(":", "")
                .replace("[", "")
                .replace("]", "");
            //  encoded contains 49b700000000
            mac = hex::decode(encoded).unwrap();
            continue;
        }
        if line.starts_with("Manu: ") {
            //  line contains Manu: FF03393161
            let encoded = line
                .split(" ")
                .collect::<Vec<&str>>()
                [1];
            //  encoded contains FF03393161
            manu = hex::decode(encoded).unwrap();
            continue;
        }
        let encoded = line
            .split("==")
            .collect::<Vec<&str>>()
            [0]
            .to_string()
            + "==";
        //  Get the Base64 decoded value, or if not Base64 encoded, just dump the value
        let mut decoded = Vec::new();
        if encoded.contains("|") {
            if encoded.contains("id") {
                //  encoded contains Value 7b226964223a2... | "{\"id\":\"nRZAdXp...Tg==
                let encoded = encoded
                    .split("|")
                    .collect::<Vec<&str>>()
                    [1];
                //  encoded contains "{\"id\":\"nRZAdXp...Tg==
                if encoded.contains(":") {
                    let encoded = encoded
                        .split(":")
                        .collect::<Vec<&str>>()
                        [1]
                        .replace("\\\"", "");
                    //  encoded contains nRZAdXp...Tg==
                    decoded = base64::decode(encoded.clone()).unwrap();
                }
            } else {
                //  encoded contains Value 28dc2dfb72... | \"(\\xdc-\\xfb...\\xe8\"
                let encoded = encoded
                    .split("|")
                    .collect::<Vec<&str>>()
                    [0];
                //  encoded contains Value 28dc2dfb72...
                if encoded.contains("Value") {
                    let encoded = encoded
                        .splitn(2, "Value")
                        .collect::<Vec<&str>>()
                        [1]
                        .replace(" ", "");
                    //  println!("encoded = {:?}", encoded);           
                    decoded = hex::decode(encoded).unwrap(); 
                }
            }
        }
        if decoded.len() > 0
            && mac.len() > 0
            && manu.len() > 0
        {
            println!("{:?},{:?},{:?},{:?}", datetime, mac, manu, decoded);
            mac = Vec::new();
            manu = Vec::new();
        }
    }
   
}
