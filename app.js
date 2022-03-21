require("dotenv").config();
require("./app/config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./app/middlewares/auth");
const User = require("./app/models/user.model");


const app = express();

app.use(express.json());

// Register
app.post("/register", async (req, res) => {
    try {
        // Get user input
        const { email, mdp } = req.body;

        // Validate user input
        if (!(email && mdp )) {
            res.status(400).send("All input is required");
        }

        // check if user already exist
        // Validate if user exist in our database
        const oldUser = await User.findOne({ email });

        if (oldUser) {
            return res.status(409).send("User Already Exist. Please Login");
        }

        //Encrypt user mdp
        let encryptedmdp = await bcrypt.hash(mdp, 10);

        // Create user in our database
        const user = await User.create({
            email: email.toLowerCase(), // sanitize: convert email to lowercase
            mdp: encryptedmdp,
        });

        // Create token
        const token = jwt.sign(
            { user_id: user._id, email },
            process.env.TOKEN_KEY,
            {
                expiresIn: "2h",
            }
        );
        // save user token
        user.token = token;

        // return new user
        res.status(201).json(user);
    } catch (err) {
        console.log(err);
    }
});

// Login
app.post("/login", async (req, res) => {
    try {
        // Get user input
        const { email, mdp } = req.body;

        // Validate user input
        if (!(email && mdp)) {
            res.status(400).send("All input is required");
        }
        // Validate if user exist in our database
        const user = await User.findOne({ email });

        if (user && (await bcrypt.compare(mdp, user.mdp))) {
            // Create token
            const token = jwt.sign(
                { user_id: user._id, email },
                process.env.TOKEN_KEY,
                {
                    expiresIn: "2h",
                }
            );

            // save user token
            user.token = token;

            // user
            res.status(200).json({token: user.token});
        }
        res.status(400).send("Invalid Credentials");
    } catch (err) {
        console.log(err);
    }

});
// Fetch users
app.get("/users", auth, async (req, res) => {
    const users = await User.find()
    res.status(200).send(users);
});

module.exports = app;