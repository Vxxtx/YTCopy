// Libraries
const express = require('express');
const fs = require("fs");
const bcrypt = require("bcrypt");
const path = require("path");
const cors = require("cors");
const fileUpload = require("express-fileupload");
const cookieParser = require("cookie-parser");
const app = express();
const port = 3000;

// Mongoose
const mongoose = require("mongoose");
var mongoDB = "";
var db;

async function InitMongoDB() {
    fs.readFile("mongodb.txt", "utf8", function(err, data) {
        if (err) {
            console.log(err);
        }
        mongoDB = data;

        mongoose.connect(mongoDB, {useNewUrlParser: true, useUnifiedTopology: true});
        db = mongoose.connection;

        db.on("error", console.error.bind(console, "connection error"));
        db.once("open", function() {
            console.log("mongoDB connected");
        });
    });
}
InitMongoDB()

const userSchema = new mongoose.Schema({
    name: String,
    password: String
});

const videoSchema = new mongoose.Schema({
    name: String,
    description: String,
    uploader: String,
    videoid: String,
    likes: Array,
    dislikes: Array,
    upload_date: String,
    length: String,
    comments: Array
});

const User = mongoose.model('User', userSchema, 'users')
const Video = mongoose.model('Video', videoSchema, 'videos')

// Logging function
function log_file(log_txt) {
    console.log(log_txt);
    fs.appendFile("log.txt", log_txt + "\n", function(err) {});
}

// Setup
app.use(express.urlencoded({extended: true} ))
app.use(express.json());
app.use(cookieParser());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public'))); // set "public" folder available for clients

app.use(fileUpload({
    createParentPath: true
}));

// set view engine, in this case ejs
app.engine('.html', require('ejs').__express);
app.set('views', __dirname + '/views');
app.set('view engine', 'html');

// Main page
app.get("", async (request, response) => {
    const check = await CheckLoginCookies(request); // check if user is logged in
    
    if (check) {
        const videos = await Video.find({});

        let videos_html = "";

        videos.forEach(x => { // iterate over the videos and make div elements for display
            let videoidonclick = `onclick="location.href = '/video?id=` + x.videoid.split(".")[0] + `';"`;
            videos_html += "<div class='videoitem' " + videoidonclick + "><video src='uploads/" + x.videoid + "'></video><div class='videoitem_right'><h3>" + x.name + "</h3><p>" + x.uploader + "</p><div class='videoitem_bottom'><p class='upload_date'>" + x.upload_date + "</p><p class='video_length'></p></div></div></div>";
        });
        
        // send generated html data
        response.render("main", {username: request.cookies.harjt_login_user, content: videos_html});
    }
    else { // if not logged in, redirect to login page
        response.redirect("/login");
    }
});

// Construct video page for user
app.get("/video", async (request, response) => {
    if (!request.query.id) {
        response.redirect("/");
        return;
    }

    const check = await CheckLoginCookies(request);
    
    if (check) {
        const video_data = await Video.findOne({videoid: request.query.id + ".mp4"});
        
        if (!video_data) {
            response.redirect("/");
            return;
        }

        let comments_data = "";
        
        video_data.comments.forEach(x => {
            comments_data += '<div class="comment"><h3>' + x[0] + '</h3><p>' + x[1] + '</p></div>';
        });

        const ownerstools = (request.cookies.harjt_login_user == video_data.uploader ? 
            "<hr><div id='owners_tools' onclick='deleteVideoConfirmation();'><p>Owner's tools</p><br><strong>Delete video</strong></div><hr>"
            : "");

        const delconfirm = (request.cookies.harjt_login_user == video_data.uploader ?
            "<div id='del_confirm' class='invisible'><div id='del_confirm_inner'><h3>Are you sure? This action will permanently delete the video.</h3><div id='del_confirm_buttons'><button id='del_button' onclick='confirmDelete();'>Delete</button> <button id='cancel_button' onclick='confirmCancel();'>Cancel</button></div></div></div>"
            : "");
            
        response.render("video", {
            username: request.cookies.harjt_login_user, 
            vid_name: video_data.name,
            vid_desc: video_data.description,
            comments: comments_data,
            likes: video_data.likes.length,
            dislikes: video_data.dislikes.length,
            likestate: video_data.likes.includes(request.cookies.harjt_login_user, 0),
            dislikestate: video_data.dislikes.includes(request.cookies.harjt_login_user, 0),
            content: "<video src='" + "/uploads/" + request.query.id + ".mp4" + "' controls></video>",
            owners_tools: ownerstools,
            del_confirm: delconfirm
        });
    }
    else {
        response.redirect("/login");
    }
});

// When a comment is posted on a video
app.post("/video", async (request, response) => {
    if (!request.body.id || request.body.id == "") {
        response.redirect("/");
        return;
    }

    const check = await CheckLoginCookies(request);
    
    if (check) {
        const user_cookie = request.cookies.harjt_login_user;
        const comment = request.body.comment;

        let video = await Video.findOne({videoid: request.body.id + ".mp4"});
        video.comments.unshift([user_cookie, comment]);
        video.save();
        
        response.json("");
        log_file(user_cookie + " commented on video " + request.body.id + " comment: " + comment);
    }
    else {
        response.redirect("/login");
    }
});

// When a video is liked or disliked. This is called by fetch in video.html <script>
app.put("/video", async (request, response) => {
    if (!request.body.id || request.body.id == "") {
        response.redirect("/");
        return;
    }
    
    const check = await CheckLoginCookies(request);
    
    if (check) {
        const user_cookie = request.cookies.harjt_login_user;

        let video = await Video.findOne({videoid: request.body.id + ".mp4"});

        // if like 
        if (request.body.type == 0) {
            const found_like = video.likes.findIndex(uploader => uploader === user_cookie);
            if (found_like != -1) { // if liked
                video.likes.splice(found_like, 1);
                video.save();
            }
            else { // if not liked
                video.likes.push(user_cookie);
                const found_dislike = video.dislikes.findIndex(uploader => uploader === user_cookie);

                if (found_dislike != -1) { // check if video is disliked, remove if is
                    video.dislikes.splice(found_dislike, 1);
                }
                
                video.save();
            }
        }
        else if(request.body.type == 1) { // if dislike
            const found_dislike = video.dislikes.findIndex(uploader => uploader === user_cookie);
            if (found_dislike != -1) { // if disliked
                video.dislikes.splice(found_dislike, 1);
                video.save();
            }
            else { // if not disliked
                video.dislikes.push(user_cookie);
                const found_like = video.likes.findIndex(uploader => uploader === user_cookie);

                if (found_like != -1) { // check if the video is liked, remove if is
                    video.likes.splice(found_like, 1);
                }
                
                video.save();
            }
        }
        response.json("");
    }
    else {
        response.redirect("/login");
    }
});

// Video deletion call
app.delete("/video", async (request, response) => {
    if (!request.body.id || request.body.id == "") {
        response.sendStatus(300).end();
        return;
    }

    const check = await CheckLoginCookies(request);
    
    if (check) {
        const user_cookie = request.cookies.harjt_login_user;

        let video = await Video.findOne({videoid: request.body.id + ".mp4"});

        if (video) {
            await video.remove(); // remove from mongodb

            // Check if video exists, if it does, then delete
            fs.stat("public/uploads/" + request.body.id + ".mp4", function(err, stats) {
                if (err) {
                    console.error(err);
                    response.sendStatus(300).end();
                    return;
                }

                // delete 
                fs.unlink("public/uploads/" + request.body.id + ".mp4", function(err) {
                    if (err) {
                        console.error(err);
                        response.sendStatus(300).end();
                        return;
                    }
                });
            });

            log_file(user_cookie + " deleted video: " + request.body.id);
            response.sendStatus(200).end();
        }
        else {
            response.sendStatus(200).end();
        }
    }
    else {
        response.sendStatus(200).end();
    }
});

// Login / logout
// Construct login page
app.get("/login", async (request, response) => {
    response.render("login", {error_text: ""});
});

// Log out when clicked on logout href and return to login page
app.get("/logout", async (request, response) => {
    const user_cookie = request.cookies.harjt_login_user;
    log_file(user_cookie + " logged out");

    response.cookie("harjt_login_user", "");
    response.cookie("harjt_login_pass", "");
    response.redirect("/login");
});

// Attempt login
app.post("/login", async (request, response) => {
    let us_input = request.body.us_input;
    let pwd_input = request.body.pwd_input;

    let UserFound = await User.findOne({"name": us_input});
    
    if (UserFound != null) {
        // Compare plaintext cookie password (maybe not best practice) 
        // to hashed and salted database password
        const pwd_valid = await bcrypt.compare(pwd_input, UserFound.password);

        if (pwd_valid) {
            log_file(us_input + " logged in");

            response.cookie("harjt_login_user", us_input);
            response.cookie("harjt_login_pass", pwd_input);

            response.redirect("/");
        }
        else {
            response.render("login", {error_text: "Wrong password"});
        }
    }
    else {
        response.render("login", {error_text: "User doesn't exist"});
    }
});

// Registration
// Construct registration page
app.get("/register", async (request, response) => {
    response.render("register", {error_text: ""});
});

// Attempt register
app.post("/register", async (request, response) => {
    let us_input = request.body.us_input;
    let pwd_input = request.body.pwd_input;
    let pwd_again_input = request.body.pwd_again_input;

    if (us_input == "") {
        response.render("register", {error_text: "Username missing"});
        return;
    }

    if (us_input.length < 3) {
        response.render("register", {error_text: "Username too short"});
        return;
    }

    if (us_input.length > 15) {
        response.render("register", {error_text: "Username too long"});
        return;
    }

    if (pwd_input == "") {
        response.render("register", {error_text: "Password missing"});
        return;
    }

    if (pwd_input.length < 5) {
        response.render("register", {error_text: "Password too short"});
        return;
    }

    if (pwd_input != pwd_again_input) {
        response.render("register", {error_text: "Passwords don't match"});
        return;
    }

    const exists = await User.exists({"name": us_input});

    if (exists == null) { // if user does not exist
        const salt = await bcrypt.genSalt(10);
        pwd_input = await bcrypt.hash(pwd_input, salt);

        const user = new User({
            name: us_input,
            password: pwd_input
        }); // make user with salted and hashed password

        await user.save();

        log_file("new user registered with name " + us_input);
        response.redirect("/login");
    }
    else {
        response.render("register", {error_text: "Username already taken"});
    }
});

// Upload
// Construct upload page 
app.get("/upload", async (request, response) => {
    const check = await CheckLoginCookies(request);
    
    if (check) {
        response.render("upload", {username: request.cookies.harjt_login_user});
    }
    else {
        response.redirect("/login");
    }
});

// Upload video
app.post("/upload", async (request, response) => {
    const check = await CheckLoginCookies(request);
    
    if (!check) {
        response.redirect("/login");
        return;
    }

    if (!request.files) {
        response.redirect("/upload");
        return;
    }

    let video = request.files.video; // get video from request data
    let videoname = Math.floor(Math.random() * 999999999) + ".mp4"; // generate randomized video name (should not use this in a public app because names could overlap)

    video.mv("./public/uploads/" + videoname); // move video to correct folder

    let date = new Date(Date.now()).toLocaleString();

    const video_data = new Video({
        name: request.body.vidname,
        description: request.body.viddesc,
        uploader: request.cookies.harjt_login_user,
        videoid: videoname,
        likes: [],
        dislikes: [],
        upload_date: date.split(" ")[0],
        length: "0",
        comments: []
    });
    video_data.save();
    
    log_file(request.cookies.harjt_login_user + " uploaded video: " + request.body.vidname + " with id: " + videoname);
    
    response.redirect("/");
});

// Function for quickly checking if user is logged in 
async function CheckLoginCookies(req) {
    const user_cookie = req.cookies.harjt_login_user;
    const pwd_cookie = req.cookies.harjt_login_pass;

    if (user_cookie && user_cookie != "" && pwd_cookie && pwd_cookie != "") {
        let UserFound = await User.findOne({"name": user_cookie});

        // check if user exists
        if (UserFound == null) { return false; }

        // check if passwords match
        const pwd_valid = await bcrypt.compare(pwd_cookie, UserFound.password);
        return pwd_valid;
    }
    return false;
}

// Initialization
app.listen(port, () => {
    console.log('Veeti Kurkela harjoitustyö listening on port 3000');
});