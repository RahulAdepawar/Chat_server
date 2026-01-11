const express = require("express");
const pool = require("./db_connect.js");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./middleware/auth.js");
const admin = require("./firebaseAdmin.js");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { Server } = require("socket.io");

module.exports = {express, pool, cors, bcrypt, cookieParser, jwt, authMiddleware, admin, fs, http, path, Server}