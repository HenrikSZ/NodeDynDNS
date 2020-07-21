const https = require('https')
const auth = require('basic-auth')
const fs = require('fs')
const url = require('url')
const isIp = require('is-ip')

const dgram = require('dgram')

const config = require('./conf.json')

let data = require('./storage.json')

const httpsOptions = {
	key: fs.readFileSync(config.https.key_path),
	passphrase: config.https.key_passphrase,
	cert: fs.readFileSync(config.https.cert_path)
}

function sendErrorResponse(res)
{
	res.statusCode = 401
	res.setHeader('WWW-Authenticate', 'Basic realm="Updating requires login"')
	res.end('Invalid authentication')
}

function getIP(req)
{
	let queryObject = url.parse(req.url, true).query
	let ipString = ""

	if (queryObject.ip)
		ipString = queryObject.ip
	else
		ipString = req.connection.remoteAddress

	return ipString
}

function handleIP(req)
{
	let ip = getIP(req)

	if (isIp.v4(ip))
		data.ipv4 = ip
	else if (isIp.v6(ip))
		data.ipv6 = ip
	else
		return new Error('Invalid IP format')

	fs.writeFileSync("./storage.json", JSON.stringify(data))

	return ip;
}

let server = https.createServer(httpsOptions, (req, res) => {
	if (isValidRequest(req))
	{
		const result = handleIP(req)

		if (result instanceof Error)
		{
			res.writeHead(400)
			res.end(result.message)
		}

		console.log(data)

		res.writeHead(200)
		res.end('IP will be set to ' + result)
	}
	else
	{
		sendErrorResponse(res)
	}
})

function validate(username, password)
{
	return config.auth.username == username && config.auth.password == password;
}

function isValidRequest(req)
{
	let credentials = auth(req)

	return credentials && validate(credentials.name, credentials.pass)
}

server.listen(8000)

const udpSocket = dgram.createSocket('udp4')

udpSocket.on('message', (msg, rinfo) => {
	handleDnsRequest(msg, rinfo)
})

udpSocket.bind(2000)


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


class Offset
{
	contructor()
	{
		this.value = 0
	}
}

class OctetGroup
{
	static read(buffer, offset)
	{
		let result = ""
		let groupLength = 0
		
		do
		{
			groupLength = buffer.readInt8(offset.value)
			offset.value++

			if (groupLength > 0)
			{
				const group = buffer.subarray(offset.value, offset.value + groupLength)
				result += group.toString('ascii')
				offset.value += groupLength
				result += '.'
			}
		} while (groupLength > 0)


		return result
	}

	static write(buffer, offset, string)
	{
		let octetGroups = string.split('.')

		for (let group of octetGroups)
		{
			offset.value = buffer.writeInt8(group.length, offset.value)
			offset.value += buffer.write(group, offset.value)
		}
	}
}

class DnsQuestion
{
	static read(buffer, offset)
	{	
		let question = new DnsQuestion()

		question.qName = OctetGroup.read(buffer, offset)

		question.qType = buffer.readInt16BE(offset.value)
		offset.value += 2
		question.qClass = buffer.readInt16BE(offset.value)
		offset.value += 2
		
		return question
	}

	size()
	{
		let size = 0
		if (this.qName)
			size += this.qName.length
		size += 4	// QType and Qclass fields
		size++		// Leading length octet of NAME
		
		return size
	}

	write(buffer, offset)
	{
		OctetGroup.write(buffer, offset, this.qName)

		offset.value = buffer.writeInt16BE(this.qType, offset.value)
		offset.value = buffer.writeInt16BE(this.qClass, offset.value)

	}
}

class DnsResourceRecord
{
	size()
	{
		let size = 0
		if (this.rName)
			size += this.rName.length
		if (this.rData)
			size += this.rData.length
		size += 10 // TYPE, CLASS, TTL, RDLENGTH
		size++ // Leading Length octet of NAME

		return size
	}

	write(buffer, offset)
	{
		OctetGroup.write(buffer, offset, this.rName)
		offset.value = buffer.writeInt16BE(this.rType, offset.value)
		offset.value = buffer.writeInt16BE(this.rClass, offset.value)
		offset.value = buffer.writeInt32BE(this.ttl, offset.value)
		offset.value = buffer.writeInt16BE(this.rData.length, offset.value)
		offset.value += buffer.write(this.rData, offset.value)
	}

	static empty()
	{
		let record = new DnsResourceRecord()

		record.rName = ""
		record.rType = 0
		record.rClass = 1
		record.ttl = 900
		record.rData = ""

		return record
	}

	static read(buffer, offset)
	{
		let record = new DnsResourceRecord()

		record.rName = OctetGroup.read(buffer, offset)
		record.rType = buffer.readInt16BE(offset.value)
		offset.value += 2
		record.rClass = buffer.readInt16BE(offset.value)
		offset.value += 2
		
		record.ttl = buffer.readInt32BE(offset.value)
		offset.value += 4

		let rDataLength = buffer.readInt16BE(offset.value)
		offset.value += 2
		record.rData = buffer.subarray(offset.value, offset.value + rDataLength).toString()
		offset.value += rDataLength

		console.log(record.rData)
		console.log(rDataLength)

		return record
	}
}

class DnsPacket
{
	readFlags(flags)
	{
		this.isResponse = 		(flags & 0b1000000000000000) >> 15
		this.opCode = 			(flags & 0b0111100000000000) >> 11
		this.isAuthority = 		(flags & 0b0000010000000000) >> 10
		this.isTruncated =		(flags & 0b0000001000000000) >> 9
		this.recursionDesired =		(flags & 0b0000000100000000) >> 8
		this.recursionAvailable =	(flags & 0b0000000010000000) >> 7
		this.responseCode =		(flags & 0b0000000000001111) >> 0
	}

	getFlags()
	{
		let flags = 0

		flags |= (this.isResponse ? 0b1 : 0b0) << 15
		flags |= this.opCode << 11
		flags |= (this.isAuthority ? 0b1 : 0b0) << 10
		flags |= (this.isTruncated ? 0b1 : 0b0) << 9
		flags |= (this.recursionDesired ? 0b1 : 0b0) << 8
		flags |= (this.recursionAvailable ? ob1 : 0b0) << 7
		flags |= this.responseCode

		return flags
	}

	write()
	{
		let size = 0

		for (let q of this.questions)
		{
			size += q.size()
		}

		for (let r of this.records)
		{
			size += r.size()
		}

		size += 12

		let buffer = Buffer.alloc(size)
		
		console.log(size)

		let offset = new Offset();

		offset.value = buffer.writeUInt16BE(this.id, offset.value)
		offset.value = buffer.writeUInt16BE(this.getFlags(), offset.value)
		offset.value = buffer.writeUInt16BE(this.questions.length, offset.value)
		offset.value = buffer.writeUInt16BE(this.records.length, offset.value)
		offset.value = buffer.writeUInt16BE(0, offset.value)
		offset.value = buffer.writeUInt16BE(0, offset.value)

		for (let q of this.questions)
		{
			q.write(buffer, offset)
		}

		for (let r of this.records)
		{
			r.write(buffer, offset)
		}

		return buffer
	}

	static read(buffer)
	{
		let packet = new DnsPacket()

		if (buffer.length < 12)
			return new Error('Too short request')

		packet.id = buffer.readInt16BE(0)
		packet.readFlags(buffer.readInt16BE(2))
		packet.questionCount = buffer.readInt16BE(4)
		packet.rrAnswersCount = buffer.readInt16BE(6)
		packet.nameServerAnswersCount = buffer.readInt16BE(8)
		packet.additionalAnswersCount = buffer.readInt16BE(10)

		packet.questions = []
		packet.records = []

		let offset = new Offset()
		offset.value = 12

		for (let i = 0; i < packet.questionCount; i++)
		{
			packet.questions.push(DnsQuestion.read(buffer, offset))
		}

		for (let i = 0; i < packet.rrAnswersCount; i++)
		{
			packet.records.push(DnsResourceRecord.read(buffer, offset))
		}

		return packet
	}

	static empty()
	{
		let packet = new DnsPacket()

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

	response()
	{
		let response = DnsPacket.empty()

		response.isResponse = true
		response.id = this.id

		return response
	}
}

function handleDnsRequest(msg, rinfo)
{
	let request = DnsPacket.read(msg)

	if (request instanceof Error)
		console.log(request)
	else
		console.log(request)

	let response = request.response()

	for (let q of request.questions)
	{
		console.log(q.qName)
		console.log(q.qType)
		if (q.qName == "home.dyn.zi-data.com.")
		{
			if (q.qType == TYPE_A)
			{
				let record = DnsResourceRecord.empty()

				record.rName = "home.dyn.zi-data.com."
				record.rType = TYPE_A
				record.rData = "Data test A"

				response.records.push(record)
			}
			else if (q.qType == TYPE_AAAA)
			{
				let record = DnsResourceRecord.empty()

				record.rName = "home.dyn.zi-data.com."
				record.rType = TYPE_AAAA
				record.rData = "Data test AAAA"

				response.records.push(record)
			}
		}
	}

	console.log(response.write())
	console.log(response)

	udpSocket.send(response.write(), rinfo.port, rinfo.address)
}

function sendTestPacket()
{
	let packet = DnsPacket.empty()

	packet.id = 1497
	packet.questionCount = 1
	packet.rrAnswerCount = 0
	packet.nameServerAnswersCount = 0
	packet.additionalAnswersCount = 0

	let question = new DnsQuestion()
	question.qName = "home.dyn.zi-data.com."
	question.qType = TYPE_AAAA
	question.qClass = 1

	packet.questions.push(question)

	console.log(packet)
	console.log(packet.write())

	let socket = dgram.createSocket('udp4')
	
	socket.on('message', (msg, rinfo) => {
		let packet = DnsPacket.read(msg)
		console.log(packet)
	})

	socket.send(packet.write(), 2000, 'localhost')
}

sendTestPacket()

