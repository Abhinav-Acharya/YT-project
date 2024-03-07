// require("dotenv").config();
import dotenv from "dotenv";
import connectDB from "./db/index.js";

dotenv.config({
  path: "./env",
});

connectDB();

/*
import express from "express";

const app = express();

const port = process.env.PORT;

(async () => {
  try {
    await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);

    app.on("error", (error) => {
      console.log("Error: ", error);
      throw error;
    });

    app.listen(port, () => {
      console.log(`App is listening on http://localhost:${port}`);
    });
  } catch (error) {
    console.error("Error: ", error);
    throw error;
  }
})(); //";" is added sometimes before (async() because in previous line ; may not have been added
*/
