const blacklist = require('./blacklist');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const { createHash } = require('crypto');

const existsAsync = promisify(blacklist.exists).bind(blacklist);
const setAsync = promisify(blacklist.set).bind(blacklist);

function geraTokenHash(token) {
    return createHash('sha256').update(token).digest('hex');
}

module.exports = {
    adiciona: async token => {
        const dataExpiracao = jwt.decode(token).exp;
        const hash = geraTokenHash(token);

        await setAsync(hash, '');
        blacklist.expireat(hash, dataExpiracao);
    },
    contemToken: async token => {
        const hash = geraTokenHash(token);
        const resultado = await existsAsync(hash);
        return resultado === 1;
    }
}