import mongoose from "mongoose";

import { DB_NAME } from "../constants.js";

const connectDB = async () => {
    try {
        //const connectionString = `${process.env.MONGODB_URI}/${DB_NAME}?retryWrites=true&w=majority&ssl=true&tls=true&&appName=general`;
        const connectionString= 'mongodb://127.0.0.1:27017/employee';
        const connectionInstance = await mongoose.connect(connectionString);
        
        console.log("Mongodb connected!!", connectionInstance.connection.host);

    } catch (e) {
        console.error("MONGODB Connection FAILED", e);
        process.exit(1);
    }
};

export default connectDB;
