
var admin = require("firebase-admin");
console.log("process.env.FIREBASE_PROJECT_ID", process.env.FIREBASE_PROJECT_ID)
console.log("process.env.FIREBASE_CLIENT_EMAIL", process.env.FIREBASE_CLIENT_EMAIL)
console.log("process.env.FIREBASE_PRIVATE_KEY", process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"))
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

module.exports = admin;
