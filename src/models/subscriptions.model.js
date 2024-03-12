import mongoose, { Schema } from "mongoose";

const subscriptionsSchema = new Schema(
  {
    subscriber: {
      type: Schema.Types.ObjectId, //one who is subscribing
      ref: "User",
    },
    channel: { type: Schema.Types.ObjectId, ref: "User" }, //one to whom 'subscriber' is subscribing
  },
  { timestamps: true }
);

export const Subscription = mongoose.model("Subscription", subscriptionsSchema);
