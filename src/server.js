import { once } from 'node:events';
import http from 'node:http';
import API from './Api.js';

async function readAll(stream) {
    let blocks = [];
    for await (let block of stream) {
        blocks.push(block);
    }
    return Buffer.concat(blocks);
}

export const httpHelp = `
Tokenized signing agent server.
curl -d '{"from": "me@tkz.id", "to": "you@tkz.id", "instrument": "instrumentId","amount": 100}' http://localhost:8080/send
curl http://localhost:8080/describe/me@tkz.id/activityId
`;

/** @param {API} api */
async function send(api, [], {from, to, instrument, amount}) {
    console.log("Send from:", from, "to:", to, "instrument:", instrument, "amount:", amount);
    const response = await api.send(from, to, instrument, amount);
    console.log("Completed", JSON.stringify(response));
    return response;
}

/** @param {API} api */
async function describe(api, [handle, activityId]) {
    const response = await api.describe(handle, activityId);
    return response;
}


const actions = {POST: {send}, GET: {describe}};

/** @param {API} api */
export async function httpServe(api, port) {

    // Create a local server to receive data from
    const server = http.createServer(async (request, response) => {
        try {
            let body;
            if (request.method == "POST") {
                body = JSON.parse(await readAll(request));
            }
            
            const method = request.method;

            let [, action, ...rest] = request.url.split("/");

            if (!actions[method][action]) {
                response.writeHead(400, { 'Content-Type': 'text/plain' });
                response.end(httpHelp);
            } else {

                try {
                    let result = await actions[method][action](api, rest, body);
                    response.writeHead(200, { 'Content-Type': 'application/json' });
                    response.end(JSON.stringify(result));
                } catch (error) {
                    if (error.status && JSON.parse(error.content)) {
                        response.writeHead(error.status, { 'Content-Type': 'application/json' });
                        response.end(error.content);
                        return;
                    }
                    throw error;
                }

                
            }
        } catch (e) {
            console.log("Request error", e);
            response.writeHead(500, { 'Content-Type': 'application/json' });
            response.end(JSON.stringify("ERROR"));
        }
    });

    server.listen(port);
    await once(server, "listening");
    console.log("Listening")
}