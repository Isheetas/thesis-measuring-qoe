/*import WebSocket from 'ws';
import https from 'http';
import express from 'express';
import fs from 'fs';
import path from 'path'*/

const WebSocket= require('ws')
const express = require('express');
const https = require('http')
const path = require('path')

//import { dirname } from 'path';

const app = express();

//const wss = new WebSocket.Server({ port: 8000 });


const server = https.createServer(app);

app.use(express.static(path.join(__dirname, 'public')));

app.get('/',function(req,res) {
    res.sendFile(__dirname + '/index.html');
  });

  app.get('/app.js', function(req,res){
    //res.sendFile(__dirname+'/app.js');
    res.sendFile(__dirname+'/app_analysis.js');
});




const wss = new WebSocket.Server({ server });



wss.on('connection', function connection(ws) {
  console.log('Someone connected')
  ws.on('message', function incoming(message) {
    //console.log(message);
    wss.clients.forEach(function each(client) {
        if (client.readyState === WebSocket.OPEN) {
          client.send(message);
        }
      });
  });

  

});

server.listen(8000);
