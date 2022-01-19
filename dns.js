"use strict";

const http = require('http')
const https = require('https')
const auth = require('basic-auth')
const fs = require('fs')
const url = require('url')
const isIp = require('is-ip')
const dgram = require('dgram')
const bcrypt = require('bcrypt')
const HashMap = require('hashmap')
const winston = require('winston')

const config = require('./conf.json')
const logger = winston.createLogger({
	level: 'info',
	format: winston.format.json(),
	transports: [
		new winston.transports.File({ filename: 'dns.log'}),
		new winston.transports.Console({ level: 'error' })
	]
})

let data

// Saves the current data (records, ips) to a json file
function saveData() {
	fs.writeFileSync('./storage.json', JSON.stringify(data))
	logger.info('dns.rr.saved')
}

// Correct signal handling
process.on('SIGINT', () => process.exit())
process.on('SIGTERM', () => process.exit())
process.on('exit', () => saveData())

class RequestRateLimiter {
	constructor(numRequests, minutes) {
		this.numRequests = numRequests
		this.minutes = minutes
		this.ipMap = new HashMap()
		this.lastRotation = Date.now() / 60000
	}

	checkIP(ip) {
		let count = this.ipMap.get(ip)

		if (Date.now() / 60000 > this.lastRotation)
		{
			this.lastRotation = Date.now() / 60000
			count = 0
		}

		count++

		if (count <= this.numRequests)
		{
			this.ipMap.set(ip, count)
			return true
		}
		else
		{
			return false
		}
	}
}

class UpdateRequestHandler {
	handle(req, res) {
		try {
			const domain = this.getTargetDomain(req)
			const result = this.handleIP(req, domain)
	
			res.writeHead(200)
			res.end(`IP set to ${result}`)
			logger.info(`update[${req.connection.remoteAddress}, ${domain} => ${result}]`)
		} catch (e) {
			switch (true) {
				case e instanceof FormatError:
					res.writeHead(422)
					break
	
				case e instanceof AuthenticationError:
					res.writeHead(401, {
						'WWW-Authenticate': 'Basic realm="Login to change IP"'
					})
					break
	
				default:
					res.writeHead(400)
			} 
			
			res.end(`Error: ${e.message}`)
		}
	}

	getTargetDomain(req) {
		let credentials = auth(req)
		if (!credentials || !credentials.name || !credentials.pass) {
			logger.warn(`update.credentials.no[${req.connection.remoteAddress}]`)
			throw new AuthenticationError("No credentials supplied")
		}

		let elem = config.domains.find((e) => (e.domain == credentials.name))
	
		if (!elem || !bcrypt.compareSync(credentials.pass, elem.password)) {
			logger.warn(`update.credentials.no[${req.connection.remoteAddress}]`)
			throw new AuthenticationError("Bad credentials supplied")
		}
	
		return elem.domain
	}

	handleIP(req, domain) {
		let ip = this.getIP(req)

		let elem = data.records.find((element) => (element.domain == domain))
		if (!elem) {
			elem = { domain: domain }
			data.records.push(elem)
		}
		
		if (isIp.v4(ip)) {
			elem.a = ip
		} else if (isIp.v6(ip)) {
			elem.aaaa = ip
		} else {
			logger.info(`update.ipaddress.bad[${req.connection.remoteAddress}, ${ip}]`)
			throw new FormatError('Invalid IP address format')
		}
			

		return ip;
	}

	getIP(req) {
		let queryObject = url.parse(req.url, true).query
		let ipString = ''

		if (queryObject.ip)
			ipString = queryObject.ip
		else
			ipString = req.connection.remoteAddress

		return ipString
	}
}

class DnsFormatError extends Error {
	constructor(message) {
		super(message)
		this.name = 'DnsFormatError'
	}
}

class FormatError extends Error {
	constructor(message) {
		super(message)
		this.name = 'FormatError'
	}
}

class AuthenticationError extends Error {
	constructor(message) {
		super(message)
		this.name = 'AuthenticationError'
	}
}

class OptionFileFormatError extends Error {
	constructor(message) {
		super(message)
		this.name = 'OptionFileError'
	}
}

class RequestRateExceededError extends Error {
	constructor(message) {
		super(message)
		this.name = 'RequestRateExceededError'
	}
}


// Possible values for the RCODE field (response code) in the
// DNS header, see RFC 1035, 4.1.1. Header section format
const RCODE_NO_ERROR        = 0
const RCODE_FORMAT_ERROR    = 1  // The name server was unable to interpret the query.
const RCODE_SERVER_FAILURE  = 2  // The name server was unable to process this query due to a problem with the name server.
const RCODE_NAME_ERROR      = 3  // This code signifies that the domain name referenced in the query does not exist.
const RCODE_NOT_IMPLEMENTED = 4  // The name server does not support the requested kind of query.
const RCODE_REFUSED         = 5  // The name server refuses to perform the specified operation for policy reasons.

// Some handy record type values, see RFC 1035, 3.2.2. TYPE values.
// Also a nice overview with numeric values: https://en.wikipedia.org/wiki/List_of_DNS_record_types
const TYPE_A     =   1  // IPv4 host address
const TYPE_NS    =   2  // an authoritative name server
const TYPE_CNAME =   5  // the canonical name for an alias
const TYPE_SOA   =   6  // marks the start of a zone of authority
const TYPE_PTR   =  12  // a domain name pointer
const TYPE_MX    =  15  // a domain name pointer
const TYPE_TXT   =  16  // text strings
const TYPE_AAAA  =  28  // IPv6 host address (see RFC 3596, 2.1 AAAA record type)
const TYPE_ALL   = 255  // A request for all records (only valid in question)


// Wrapper object to make passing around buffer offsets easier
class Offset {
	constructor() {
		this.value = 0
	}
}

// Class with static methods to read and write domains in the format specified by RFC 1035
class OctetGroup {
	static read(buffer, offset) {
		let result = ''
		let groupLength = 0
		let usedPointer = false
		
		do {
			groupLength = buffer.readUInt8(offset.value)
			offset.value++
			
			if (groupLength > 0) {
				if (((groupLength & 0b10000000) >> 7) == 1
					&& ((groupLength & 0b01000000) >> 6) == 1) {
					// Message pointer

					if (usedPointer)
						throw new DnsFormatError('Octet Group Pointer can only be used once per domain name')
					
					usedPointer = true
					offset = new Offset()
					offset.value = groupLength & 0b00111111
					continue
				}

				const group = buffer.subarray(offset.value, offset.value + groupLength)
				result += group.toString('ascii')
				offset.value += groupLength
				result += '.'
			}
		} while (groupLength > 0)

		return result
	}

	static write(buffer, offset, string) {
		let octetGroups = string.split('.')

		octetGroups.forEach((group) => {
			offset.value = buffer.writeInt8(group.length, offset.value)
			offset.value += buffer.write(group, offset.value)
		})
	}
}


// Class to read and write DNS questions
class DnsQuestion {
	static read(buffer, offset) {
		let question = new DnsQuestion()

		question.qName = OctetGroup.read(buffer, offset)
		question.qType = buffer.readUInt16BE(offset.value)
		offset.value += 2
		question.qClass = buffer.readUInt16BE(offset.value)
		offset.value += 2

		return question
	}

	static empty() {
		return new DnsQuestion()
	}

	size() {
		let size = 0
		if (this.qName)
			size += this.qName.length
		size += 4	// QType and Qclass fields
		size++		// Leading length octet of NAME
	
		return size
	}

	write(buffer, offset) {
		OctetGroup.write(buffer, offset, this.qName)

		offset.value = buffer.writeInt16BE(this.qType, offset.value)
		offset.value = buffer.writeInt16BE(this.qClass, offset.value)
	}
}

// Class to read and write DNS RRs
class DnsResourceRecord {
	static empty() {
		let record = new DnsResourceRecord()

		record.rName = ''
		record.rType = 0
		record.rClass = 1
		record.ttl = 300
		record.rData = ''

		return record
	}

	static read() {
		let record = new DnsResourceRecord()

		record.rName = OctetGroup.read(buffer, offset)
		record.rType = buffer.readUInt16BE(offset.value)
		offset.value += 2
		record.rClass = buffer.readUInt16BE(offset.value)
		offset.value += 2
		
		record.ttl = buffer.readUInt32BE(offset.value)
		offset.value += 4

		record.readData(buffer, offset)
		
		return record
	}

	size() {
		let size = 0
		if (this.rName)
			size += this.rName.length
		switch (this.rType) {
			case TYPE_A:
				size += 4
				break
			case TYPE_AAAA:
				size += 16
				break
		}
		size += 10 // TYPE, CLASS, TTL, RDLENGTH
		size++ // Leading Length octet of NAME

		return size
	}

	writeData(buffer, offset) {
		switch (this.rType) {
			case TYPE_A:
				offset.value = buffer.writeUInt16BE(4, offset.value)
				
				let octets = this.rData.split('.')
				octets.forEach((e) => {
					offset.value = buffer.writeUInt8(parseInt(e, 10), offset.value)
				})
				break
			
			case TYPE_AAAA:
				offset.value = buffer.writeUInt16BE(16, offset.value)
				
				let chunks = this.rData.split(':')
				for (let c of chunks) {
					if (c ==  '')
						for (let i = 0; i < 8 + 1 - chunks.length; i++)
							offset.value = buffer.writeUInt16BE(0, offset.value)
					else
						offset.value = buffer.writeUInt16BE(parseInt(c, 16), offset.value)
				}
				break
		}
	}

	write(buffer, offset) {
		OctetGroup.write(buffer, offset, this.rName)
		offset.value = buffer.writeUInt16BE(this.rType, offset.value)
		offset.value = buffer.writeUInt16BE(this.rClass, offset.value)
		offset.value = buffer.writeUInt32BE(this.ttl, offset.value)
		this.writeData(buffer, offset)
	}

	readData(buffer, offset) {
		let rDataLength = buffer.readUInt16BE(offset.value)
		offset.value += 2
	
		switch (this.rType) {
			case TYPE_A:
				this.rData = ''
				for (let i = 0; i < 4; i++) {
					let block = buffer.readUInt8(offset.value)
					this.rData += block.toString()
	
					if (i < 3) this.rData += '.'
					offset.value++
				}
				break
			case TYPE_AAAA:
				this.rData = ''
	
				for (let i = 0; i < 8; i++) {
					let block = buffer.readUInt16BE(offset.value)
					this.rData += block.toString(16)	
	
					if (i < 7) this.rData += ':'
	
					offset.value += 2
				}
				break
		}

		offset.value += rDataLength
	}
}

// Class to read and write whole DNS message
class DnsMessage {
	static empty() {
		let packet = new DnsMessage()

		packet.isResponse = false
		packet.opCode = 0
		packet.isAuthority = false
		packet.isTruncated = false
		packet.recursionDesired = false
		packet.recursionAvailable = false
		packet.responseCode = 0

		packet.questions = []
		packet.records = []

		return packet
	}

	static read(buffer) {
		let packet = DnsMessage.empty()

		if (buffer.length < 12)
			throw new DnsFormatError('DNS Request too short')

		try {
			packet.id = buffer.readUInt16BE(0)
			packet.readFlags(buffer.readUInt16BE(2))

			let questionCount = buffer.readUInt16BE(4)
			let rrAnswersCount = buffer.readUInt16BE(6)
			let nameServerAnswersCount = buffer.readUInt16BE(8)
			let additionalAnswersCount = buffer.readUInt16BE(10)

			let offset = new Offset()
			offset.value = 12

			for (let i = 0; i < questionCount; i++)
				packet.questions.push(DnsQuestion.read(buffer, offset))

			for (let i = 0; i < rrAnswersCount; i++)
				packet.records.push(DnsResourceRecord.read(buffer, offset))
		} catch (e) {
			let err = new DnsFormatError('Malformed DNS Request')
			err.packet = packet
			throw err
		}

		return packet
	}

	readFlags(flags) {
		this.isResponse = 		!!((flags & 0b1000000000000000) >> 15)
		this.opCode = 			(flags & 0b0111100000000000) >> 11
		this.isAuthority = 		!!((flags & 0b0000010000000000) >> 10)
		this.isTruncated =		!!((flags & 0b0000001000000000) >> 9)
		this.recursionDesired =		!!((flags & 0b0000000100000000) >> 8)
		this.recursionAvailable =	!!((flags & 0b0000000010000000) >> 7)
		this.responseCode =		(flags & 0b0000000000001111) >> 0
	}

	getFlags() {
		let flags = 0

		flags |= (this.isResponse ? 0b1 : 0b0) << 15
		flags |= this.opCode << 11
		flags |= (this.isAuthority ? 0b1 : 0b0) << 10
		flags |= (this.isTruncated ? 0b1 : 0b0) << 9
		flags |= (this.recursionDesired ? 0b1 : 0b0) << 8
		flags |= (this.recursionAvailable ? 0b1 : 0b0) << 7
		flags |= this.responseCode << 0

		return flags
	}

	write() {
		let size = 0

		this.questions.forEach((q) => size += q.size())
		this.records.forEach((r) => size += r.size())

		size += 12

		let buffer = Buffer.alloc(size)
		let offset = new Offset();

		offset.value = buffer.writeUInt16BE(this.id, offset.value)			// ID 
		offset.value = buffer.writeUInt16BE(this.getFlags(), offset.value)		// Flags
		offset.value = buffer.writeUInt16BE(this.questions.length, offset.value)	// Questions count
		offset.value = buffer.writeUInt16BE(this.records.length, offset.value)		// Records count
		offset.value = buffer.writeUInt16BE(0, offset.value)				// Name server count
		offset.value = buffer.writeUInt16BE(0, offset.value)				// Additionals count

		this.questions.forEach((q) => q.write(buffer, offset))
		this.records.forEach((r) => r.write(buffer, offset))

		return buffer
	}

	response() {
		let response = DnsMessage.empty()

		response.isResponse = true
		response.id = this.id
		response.isAuthority = true
		response.questions = this.questions

		return response
	}

	error(errorCode) {
		let response = DnsMessage.empty()

		response.isReponse = true
		response.id = this.id
		response.isAuthority = true
		response.responseCode = errorCode

		return response
	}
}

class DnsRequestHandler {
	constructor(requestRateLimiter, privilegeManager) {
		this.requestRateLimiter = requestRateLimiter
		this.udp4Socket = dgram.createSocket('udp4')
		this.udp4Socket.on('message', (msg, rinfo) => {
			try {
				this.handle(msg, rinfo)
			} catch (e) {
				if (!e instanceof RequestRateExceededError)
					logger.error(`dns.error[${e.name}, ${e.message}]`)
			}
		})
		this.udp4Socket.bind(53, config.dns.address, () => {
			logger.info('dns.port[53]')
			privilegeManager.drop()
		})
	}

	handle(msg, rinfo) {
		if (!this.requestRateLimiter.checkIP(rinfo.address)) {
			logger.warn(`dns.throttling[${rinfo.address}]`)
			throw new RequestRateExceededError(`Too many DNS request from address ${rinfo.address}`)
		}

		let request

		try {
			request = DnsMessage.read(msg)
		} catch (e) {
			if (e.packet) {
				let errorCode

				switch (true) {
					case e instanceof DnsFormatError:
						logger.warn(`dns.error.format[${rinfo.address}]`)
						errorCode = RCODE_FORMAT_ERROR
						break

					default:
						logger.warn(`dns.error[${rinfo.address}, ${e.name}, ${e.message}]`)
						errorCode = RCODE_NO_ERROR
				}
				this.udp4Socket.send(e.packet.error(errorCode).write(), rinfo.port, rinfo.address)
			}

			return
		}
		
		let response = request.response()
		let domainAvailable = false

		request.questions.forEach((q) => {
			let recordData = data.records.find((e) => (e.domain == q.qName))

			if (recordData) {
				domainAvailable = true

				let record = DnsResourceRecord.empty()
				record.rName = q.qName

				if (q.qType == TYPE_A && recordData.a) {
					record.rType = TYPE_A
					record.rData = recordData.a
					response.records.push(record)
				} else if (q.qType == TYPE_AAAA && recordData.aaaa) {
					record.rType = TYPE_AAAA
					record.rData = recordData.aaaa
					response.records.push(record)
				}
			}
		})

		if (!domainAvailable)
			response.responseCode = 3

		logger.verbose(`dns.request[${rinfo.address}, ${rinfo.port}]`)
		logger.debug(request.questions)

		logger.debug(response.records)

		this.udp4Socket.send(response.write(), rinfo.port, rinfo.address)
	}
}

class HttpsUpdater {
	constructor(updateRequestHandler, privilegeManager) {
		if (config.https) {
			if (!config.https.key_path || !config.https.cert_path || !config.https.port) {
				logger.error('https.options.notset[key_path, cert_path, port]')
				throw new OptionFileFormatError("Options key_path, cert_path and port have to be set for the https service");
			}

			const httpsOptions = {
				key: '',
				cert: ''
			}

			fs.promises.readFile(config.https.key_path).then((key) => {
				httpsOptions.key = key
			}).then(() => {
				fs.promises.readFile(config.https.cert_path).then((cert) => {
					httpsOptions.cert = cert
				}).then(() => {
					logger.info(`https.key[${config.https.key_path}]`)
					logger.info(`https.certificate[${config.https.cert_path}]`)

					this.httpsServer = https.createServer(httpsOptions, (req, res) => {
						updateRequestHandler.handle(req, res)
					})
					this.httpsServer.listen(config.https.port, () => {
						logger.info(`https.port[${config.https.port}]`)
						privilegeManager.drop()
					})
				}).catch((err) => logger.error(err))
			}).catch((err) => logger.error(err))
		} else {
			privilegeManager.drop()
		}
	}
}

class HttpUpdater {
	constructor(updateRequestHandler, privilegeManager) {
		if (config.http) {
			if (!config.http.port) {
				logger.error('http.port.notset')
				throw new OptionFileFormatError("Option port has to be set for the http service");
			}

			this.httpServer = http.createServer((req, res) => {
				updateRequestHandler.handle(req, res)
			})
			this.httpServer.listen(config.http.port, () => {
				logger.info(`http.port[${config.http.port}]`)
				privilegeManager.drop()
			})
		}
		else {
			privilegeManager.drop()
		}
	}
}

class PrivilegeManager {
	constructor() {
		this.toBePrivileged = 3
	}

	drop() {
		if (--this.toBePrivileged === 0) {
			if (process.setgid && process.setiud) {
				process.setgid(config.system.group)
				process.setuid(config.system.user)
			}
	
			logger.info(`sys.user[${config.system.user}]`)
			logger.info(`sys.group[${config.system.group}]`)
		}
	}
}

fs.access('./storage.json', (err) => {
	if (err)
		data = { records: [] }
	else
		data = require('./storage.json')

	const privilegeManager = new PrivilegeManager()
	const updateRequestHandler = new UpdateRequestHandler()
	const requestRateLimiter = new RequestRateLimiter(10, 1)
	new DnsRequestHandler(requestRateLimiter, privilegeManager)
	new HttpUpdater(updateRequestHandler, privilegeManager)
	new HttpsUpdater(updateRequestHandler, privilegeManager)
})
