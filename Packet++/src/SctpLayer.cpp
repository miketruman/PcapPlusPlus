#define LOG_MODULE PacketLogModuleSctpLayer

#include "EndianPortable.h"
#include "SctpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include "HttpLayer.h"
#include "SSLLayer.h"
#include "SipLayer.h"
#include "BgpLayer.h"
#include "SSHLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <string.h>
#include <sstream>

namespace pcpp
{

#define SCTPOPT_DUMMY 0xff

/// ~~~~~~~~~~~~~~~~
/// SctpChunkBuilder
/// ~~~~~~~~~~~~~~~~
/*
SctpChunkBuilder::SctpChunkBuilder(NopEolOptionTypes optionType)
{
	switch (optionType)
	{
	case EOL:
		init((uint8_t)PCPP_SCTPOPT_EOL, NULL, 0);
		break;
	case NOP:
	default:
		init((uint8_t)PCPP_SCTPOPT_NOP, NULL, 0);
		break;
	}
}
*/
/*
SctpChunk SctpChunkBuilder::build() const
{
	size_t optionSize = m_RecValueLen + 2*sizeof(uint8_t);

	if (m_RecType == (uint8_t)PCPP_SCTPOPT_EOL || m_RecType == (uint8_t)PCPP_SCTPOPT_NOP)
	{
		if (m_RecValueLen != 0)
		{
			LOG_ERROR("SCTP NOP and SCTP EOL options are 1-byte long and don't have option value. Tried to set option value of size %d", m_RecValueLen);
			return SctpChunk(NULL);
		}

		optionSize = 1;
	}

	uint8_t* recordBuffer = new uint8_t[optionSize];
	memset(recordBuffer, 0, optionSize);
	recordBuffer[0] = m_RecType;
	if (optionSize > 1)
	{
		recordBuffer[1] = (uint8_t)optionSize;
		if (optionSize > 2 && m_RecValue != NULL)
			memcpy(recordBuffer+2, m_RecValue, m_RecValueLen);
	}

	return SctpChunk(recordBuffer);
}
*/


/// ~~~~~~~~
/// SctpLayer
/// ~~~~~~~~

/*
SctpChunk SctpLayer::getSctpChunk(SctpChunkType option) const
{
	return m_OptionReader.getTLVRecord((uint8_t)option, getOptionsBasePtr(), getHeaderLen() - sizeof(sctphdr));
}*/

/*
SctpChunk SctpLayer::getFirstSctpChunk() const
{
	//return m_OptionReader.getFirstTLVRecord(getOptionsBasePtr(), getHeaderLen() - sizeof(sctphdr));
}
*/

/*
SctpChunk SctpLayer::getNextSctpChunk(SctpChunk& sctpChunk) const
{
	SctpChunk nextOpt = m_OptionReader.getNextTLVRecord(sctpChunk, getOptionsBasePtr(), getHeaderLen() - sizeof(sctphdr));
	if (nextOpt.isNotNull() && nextOpt.getType() == SCTPOPT_DUMMY)
		return SctpChunk(NULL);

	return nextOpt;	
}
*/

size_t SctpLayer::getSctpChunkCount() const
{
//	return m_OptionReader.getTLVRecordCount(getOptionsBasePtr(), getHeaderLen() - sizeof(sctphdr));
}


/*
SctpChunk SctpLayer::addSctpChunkAt(const SctpChunkBuilder& optionBuilder, int offset)
{
	
	SctpChunk newOption = optionBuilder.build();
	if (newOption.isNull())
		return newOption;

	// calculate total SCTP option size
	SctpChunk curOpt = getFirstSctpChunk();
	size_t totalOptSize = 0;
	while (!curOpt.isNull())
	{
		totalOptSize += curOpt.getTotalSize();
		curOpt = getNextSctpChunk(curOpt);
	}
	totalOptSize += newOption.getTotalSize();

	size_t sizeToExtend = newOption.getTotalSize();

	if (!extendLayer(offset, sizeToExtend))
	{
		LOG_ERROR("Could not extend SctpLayer in [%d] bytes", (int)sizeToExtend);
		newOption.purgeRecordData();
		return SctpChunk(NULL);
	}

	memcpy(m_Data + offset, newOption.getRecordBasePtr(), newOption.getTotalSize());

	newOption.purgeRecordData();

	adjustSctpChunkTrailer(totalOptSize);

	m_OptionReader.changeTLVRecordCount(1);

	uint8_t* newOptPtr = m_Data + offset;

	return SctpChunk(newOptPtr);
	
}
*/

void SctpLayer::adjustSctpChunkTrailer(size_t totalOptSize)
{
	/*
	int newNumberOfTrailingBytes = 0;
	while ((totalOptSize + newNumberOfTrailingBytes) % 4 != 0)
		newNumberOfTrailingBytes++;

	if (newNumberOfTrailingBytes < m_NumOfTrailingBytes)
		shortenLayer(sizeof(sctphdr)+totalOptSize, m_NumOfTrailingBytes - newNumberOfTrailingBytes);
	else if (newNumberOfTrailingBytes > m_NumOfTrailingBytes)
		extendLayer(sizeof(sctphdr)+totalOptSize, newNumberOfTrailingBytes - m_NumOfTrailingBytes);

	m_NumOfTrailingBytes = newNumberOfTrailingBytes;

	for (int i = 0; i < m_NumOfTrailingBytes; i++)
		m_Data[sizeof(sctphdr) + totalOptSize + i] = SCTPOPT_DUMMY;

	getSctpHeader()->dataOffset = (sizeof(sctphdr) + totalOptSize + m_NumOfTrailingBytes)/4;
	*/
}

uint16_t SctpLayer::calculateChecksum(bool writeResultToPacket)
{
	/*
	sctphdr* sctpHdr = getSctpHeader();
	uint16_t checksumRes = 0;
	uint16_t currChecksumValue = sctpHdr->headerChecksum;

	if (m_PrevLayer != NULL)
	{
		sctpHdr->headerChecksum = 0;
		ScalarBuffer<uint16_t> vec[2];
		LOG_DEBUG("data len =  %d", (int)m_DataLen);
		vec[0].buffer = (uint16_t*)m_Data;
		vec[0].len = m_DataLen;

		if (m_PrevLayer->getProtocol() == IPv4)
		{
			uint32_t srcIP = ((IPv4Layer*)m_PrevLayer)->getSrcIpAddress().toInt();
			uint32_t dstIP = ((IPv4Layer*)m_PrevLayer)->getDstIpAddress().toInt();
			uint16_t pseudoHeader[6];
			pseudoHeader[0] = srcIP >> 16;
			pseudoHeader[1] = srcIP & 0xFFFF;
			pseudoHeader[2] = dstIP >> 16;
			pseudoHeader[3] = dstIP & 0xFFFF;
			pseudoHeader[4] = 0xffff & htobe16(m_DataLen);
			pseudoHeader[5] = htobe16(0x00ff & PACKETPP_IPPROTO_SCTP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 12;
			checksumRes = computeChecksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);


		}
		else if (m_PrevLayer->getProtocol() == IPv6)
		{
			uint16_t pseudoHeader[18];
			((IPv6Layer*)m_PrevLayer)->getSrcIpAddress().copyTo((uint8_t*)pseudoHeader);
			((IPv6Layer*)m_PrevLayer)->getDstIpAddress().copyTo((uint8_t*)(pseudoHeader+8));
			pseudoHeader[16] = 0xffff & htobe16(m_DataLen);
			pseudoHeader[17] = htobe16(0x00ff & PACKETPP_IPPROTO_SCTP);
			vec[1].buffer = pseudoHeader;
			vec[1].len = 36;
			checksumRes = computeChecksum(vec, 2);
			LOG_DEBUG("calculated checksum = 0x%4X", checksumRes);
		}
	}

	if(writeResultToPacket)
		sctpHdr->headerChecksum = htobe16(checksumRes);
	else
		sctpHdr->headerChecksum = currChecksumValue;

	return checksumRes;
	*/
}

void SctpLayer::initLayer()
{
	m_DataLen = sizeof(sctphdr);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = SCTP;
	m_NumOfTrailingBytes = 0;
	/*
	getSctpHeader()->dataOffset = sizeof(sctphdr)/4;
	*/
}

SctpLayer::SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet)
{
	m_Protocol = SCTP;
	m_NumOfTrailingBytes = 0;
}

SctpLayer::SctpLayer()
{
	initLayer();
}

void SctpLayer::copyLayerData(const SctpLayer& other)
{
//	m_OptionReader = other.m_OptionReader;
//	m_NumOfTrailingBytes = other.m_NumOfTrailingBytes;
}

SctpLayer::SctpLayer(const SctpLayer& other) : Layer(other)
{
	copyLayerData(other);
}

SctpLayer& SctpLayer::operator=(const SctpLayer& other)
{
	Layer::operator=(other);

	copyLayerData(other);

	return *this;
}

void SctpLayer::parseNextLayer()
{
	
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	uint8_t* payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;
	sctphdr* sctpHder = getSctpHeader();
	uint16_t portDst = be16toh(sctpHder->portDst);
	uint16_t portSrc = be16toh(sctpHder->portSrc);
/*
	if (HttpMessage::isHttpPort(portDst) && HttpRequestFirstLine::parseMethod((char*)payload, payloadLen) != HttpRequestLayer::HttpMethodUnknown)
		m_NextLayer = new HttpRequestLayer(payload, payloadLen, this, m_Packet);
	else if (HttpMessage::isHttpPort(portSrc) && HttpResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != HttpResponseLayer::HttpStatusCodeUnknown)
		m_NextLayer = new HttpResponseLayer(payload, payloadLen, this, m_Packet);
	else if (SSLLayer::IsSSLMessage(portSrc, portDst, payload, payloadLen))
		m_NextLayer = SSLLayer::createSSLMessage(payload, payloadLen, this, m_Packet);
	else if (SipLayer::isSipPort(portDst))
	{
		if (SipRequestFirstLine::parseMethod((char*)payload, payloadLen) != SipRequestLayer::SipMethodUnknown)
			m_NextLayer = new SipRequestLayer(payload, payloadLen, this, m_Packet);
		else if (SipResponseFirstLine::parseStatusCode((char*)payload, payloadLen) != SipResponseLayer::SipStatusCodeUnknown)
			m_NextLayer = new SipResponseLayer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
	else if (BgpLayer::isBgpPort(portSrc, portDst))
		m_NextLayer = BgpLayer::parseBgpLayer(payload, payloadLen, this, m_Packet);
	else if (SSHLayer::isSSHPort(portSrc, portDst))
		m_NextLayer = SSHLayer::createSSHMessage(payload, payloadLen, this, m_Packet);
	else
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		*/
}

void SctpLayer::computeCalculateFields()
{
	/*
	sctphdr* sctpHdr = getSctpHeader();

	sctpHdr->dataOffset = getHeaderLen() >> 2;
	calculateChecksum(true);*/
}

std::string SctpLayer::toString() const
{
	std::string result = "SCTP Layer, ";
	/*
	sctphdr* hdr = getSctpHeader();
	
	if (hdr->synFlag)
	{
		if (hdr->ackFlag)
			result += "[SYN, ACK], ";
		else
			result += "[SYN], ";
	}
	else if (hdr->finFlag)
	{
		if (hdr->ackFlag)
			result += "[FIN, ACK], ";
		else
			result += "[FIN], ";
	}
	else if (hdr->ackFlag)
		result += "[ACK], ";

	std::ostringstream srcPortStream;
	srcPortStream << be16toh(hdr->portSrc);
	std::ostringstream dstPortStream;
	dstPortStream << be16toh(hdr->portDst);
	result += "Src port: " + srcPortStream.str() + ", Dst port: " + dstPortStream.str();
*/
	return result;
}

} // namespace pcpp
