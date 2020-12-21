#ifndef PACKETPP_SCTP_LAYER
#define PACKETPP_SCTP_LAYER

#include "Layer.h"
#include "TLVData.h"
#include <string.h>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @struct sctphdr
	 * Represents an SCTP protocol header
	 */
#pragma pack(push,1)
	struct sctphdr {
		/** Source SCTP port */
		uint16_t portSrc;
		/** Destination SCTP port */
		uint16_t portDst;
		/** Verification Tag */
		uint32_t verificationTag;
		/** The 32-bit checksum field is used for error-checking of the header and data */
		uint32_t checksum;
	};
#pragma pack(pop)


	/**
	 * SCTP options types
	 */
	enum SctpChunkType {
		/** Padding */
		PCPP_SCTPOPT_NOP =       1,
		/** End of options */
		PCPP_SCTPOPT_EOL =       0
	};


	// SCTP option lengths

	/** pcpp::PCPP_SCTPOPT_NOP length */
#define PCPP_SCTPOLEN_NOP            1
	/** pcpp::PCPP_SCTPOPT_EOL length */
#define PCPP_SCTPOLEN_EOL            1

	/**
	 * @class SctpChunk
	 * A wrapper class for SCTP options. This class does not create or modify SCTP option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	/*
	class SctpChunk : public TLVRecord
	{
	public:
		SctpChunk(uint8_t* optionRawData) : TLVRecord(optionRawData) { }
		~SctpChunk() { }
		SctpChunkType getSctpChunkType() const
		{
			if (m_Data == NULL)
				return SCTPOPT_Unknown;

			return (SctpChunkType)m_Data->recordType;
		}

		size_t getTotalSize() const
		{
			if (m_Data == NULL)
				return (size_t)0;

			if (m_Data->recordType == (uint8_t)PCPP_SCTPOPT_NOP || m_Data->recordType == (uint8_t)PCPP_SCTPOPT_EOL)
				return sizeof(uint8_t);

			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize() const
		{
			if (m_Data == NULL)
				return 0;

			if (m_Data->recordType == (uint8_t)PCPP_SCTPOPT_NOP || m_Data->recordType == (uint8_t)PCPP_SCTPOPT_EOL)
				return (size_t)0;

			return (size_t)m_Data->recordLen - (2*sizeof(uint8_t));
		}
	};


*/
	/**
	 * @class SctpLayer
	 * Represents a SCTP (Transmission Control Protocol) protocol layer
	 */
	class SctpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref sctphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SctpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new SCTP header with zero SCTP options
		 */
		SctpLayer();

		~SctpLayer() {}

		/**
		 * A copy constructor that copy the entire header from the other SctpLayer (including SCTP options)
		 */
		SctpLayer(const SctpLayer& other);

		/**
		 * An assignment operator that first delete all data from current layer and then copy the entire header from the other SctpLayer (including SCTP options)
		 */
		SctpLayer& operator=(const SctpLayer& other);

		/**
		 * Get a pointer to the SCTP header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the @ref sctphdr
		 */
		sctphdr* getSctpHeader() const { return (sctphdr*)m_Data; }

		/**
		 * Get a SCTP option by type
		 * @param[in] option SCTP option type to retrieve
		 * @return An SctpChunk object that contains the first option that matches this type, or logical NULL
		 * (SctpChunk#isNull() == true) if no such option found
		 */
	//	SctpChunk getSctpChunk(SctpChunkType option) const;

		/**
		 * @return The first SCTP option in the packet. If the current layer contains no options the returned value will contain
		 * a logical NULL (SctpChunk#isNull() == true)
		 */
//		SctpChunk getFirstSctpChunk() const;

		/**
		 * Get the SCTP option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical NULL (SctpChunk#isNull() == true)
		 * @param[in] sctpChunk A SCTP option object that exists in the current layer
		 * @return A SctpChunk object that contains the SCTP option data that comes next, or logical NULL if the given
		 * SCTP option: (1) was the last one; or (2) contains a logical NULL; or (3) doesn't belong to this packet
		 */
	//	SctpChunk getNextSctpChunk(SctpChunk& sctpChunk) const;

		/**
		 * @return The number of SCTP options in this layer
		 */
		size_t getSctpChunkCount() const;

		/**
		 * Calculate the checksum from header and data and possibly write the result to @ref sctphdr#headerChecksum
		 * @param[in] writeResultToPacket If set to true then checksum result will be written to @ref sctphdr#headerChecksum
		 * @return The checksum result
		 */
		uint16_t calculateChecksum(bool writeResultToPacket);

		/**
		 * The static method makes validation of input data
		 * @param[in] data The pointer to the beginning of byte stream of SCTP packet
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent a SCTP packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: HttpRequestLayer, HttpResponseLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref sctphdr + all SCTP options
		 */
		size_t getHeaderLen() const { return 8;}

		/**
		 * Calculate @ref sctphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }

	private:

//		TLVRecordReader<SctpChunk> m_OptionReader;
		int m_NumOfTrailingBytes;

		void initLayer();
		uint8_t* getOptionsBasePtr() const { return m_Data + sizeof(sctphdr); }
	//	SctpChunk addSctpChunkAt(const SctpChunkBuilder& optionBuilder, int offset);
		void adjustSctpChunkTrailer(size_t totalOptSize);
		void copyLayerData(const SctpLayer& other);
	};


	// implementation of inline methods

	bool SctpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		const sctphdr* hdr = reinterpret_cast<const sctphdr*>(data);
		return dataLen >= sizeof(sctphdr);
//			&& hdr->dataOffset >= 5 /* the minimum SCTP header size */
//			&& dataLen >= hdr->dataOffset * sizeof(uint32_t);
	}

} // namespace pcpp

#endif /* PACKETPP_SCTP_LAYER */
