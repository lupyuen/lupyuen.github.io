:: copy %userprofile%\lupyuen.resume.json resume.json
call scripts\gen-resume-html.cmd
call scripts\gen-resume-pdf.cmd

cd json-to-rss
cargo run >..\rss.xml
