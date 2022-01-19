"use strict";

const bcrypt = require('bcrypt')
const optionFile = require('./conf.json')
const readline = require('readline')
const fs = require('fs')

let rl = readline.createInterface(
    {
        input: process.stdin,
        output: process.stdout
    }
)

const domains = optionFile.domains
domains.forEach((domain, index) => console.log(`${index}: ${domain.domain}`))

rl.question('Enter index of the domain you want to change the password for:\n', (index) => {
    rl.question(`Enter password for ${domains[index].domain}:`, (password) => {
        domains[index].password = bcrypt.hashSync(password, bcrypt.genSaltSync())
        fs.writeFileSync('./conf.json', JSON.stringify(optionFile, null, 2))
        process.exit()
    })
})

