export async function createJWT(kid, privateKey, claims) {
    let header =
        Buffer.from(
            JSON.stringify({
                typ: 'JWT',
                alg: 'ES256',
                kid,
            }),
        ).toString("base64url");

    let payload = Buffer.from(JSON.stringify(claims)).toString("base64url");

    let signature =
        Buffer.from(
            await crypto.subtle.sign(
                { name: 'ECDSA', hash: { name: 'SHA-256' } },
                privateKey,
                Buffer.from(`${header}.${payload}`),
            ),
        ).toString("base64url");


    return `${header}.${payload}.${signature}`;
}

function parseJWT(jwt) {
    const [header, payload, signature] = jwt.split(".").map(section => Buffer.from(section, "base64url"));
    return {
        header: JSON.parse(header),
        payload: JSON.parse(payload),
    };
}



export function expiredFraction(jwt, createdAt) {
    let { payload } = parseJWT(jwt);
    let issued = payload.iat || createdAt;
    let created = createdAt || payload.iat;
    let expires = payload.expires;
    let now = Date.now() / 1e3;
    return (now - created) / (expires - issued)
}
