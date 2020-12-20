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
		uint32_t	checksum;
	};
#pragma pack(pop)


	/**
	 * SCTP options types
	 */
	enum SctpOptionType {
		/** Padding */
		PCPP_SCTPOPT_NOP =       1,
		/** End of options */
		PCPP_SCTPOPT_EOL =       0,
		/** Segment size negotiating */
		SCTPOPT_MSS =          	2,
		/** Window scaling */
		PCPP_SCTPOPT_WINDOW =    3,
		/** SACK Permitted */
		SCTPOPT_SACK_PERM =      4,
		/** SACK Block */
		PCPP_SCTPOPT_SACK =      5,
		/** Echo (obsoleted by option ::PCPP_SCTPOPT_TIMESTAMP) */
		SCTPOPT_ECHO =           6,
		/** Echo Reply (obsoleted by option ::PCPP_SCTPOPT_TIMESTAMP) */
		SCTPOPT_ECHOREPLY =      7,
		/** SCTP Timestamps */
		PCPP_SCTPOPT_TIMESTAMP = 8,
		/** CC (obsolete) */
		SCTPOPT_CC =             11,
		/** CC.NEW (obsolete) */
		SCTPOPT_CCNEW =          12,
		/** CC.ECHO(obsolete) */
		SCTPOPT_CCECHO =         13,
		/** MD5 Signature Option */
		SCTPOPT_MD5 =            19,
		/** Multipath SCTP */
		SCTPOPT_MPSCTP =          0x1e,
		/** SCPS Capabilities */
		SCTPOPT_SCPS =           20,
		/** SCPS SNACK */
		SCTPOPT_SNACK =          21,
		/** SCPS Record Boundary */
		SCTPOPT_RECBOUND =       22,
		/** SCPS Corruption Experienced */
		SCTPOPT_CORREXP =        23,
		/** Quick-Start Response */
		SCTPOPT_QS =             27,
		/** User Timeout Option (also, other known unauthorized use) */
		SCTPOPT_USER_TO =        28,
		/** RFC3692-style Experiment 1 (also improperly used for shipping products) */
		SCTPOPT_EXP_FD =         0xfd,
		/** RFC3692-style Experiment 2 (also improperly used for shipping products) */
		SCTPOPT_EXP_FE =         0xfe,
		/** Riverbed probe option, non IANA registered option number */
		SCTPOPT_RVBD_PROBE =     76,
		/** Riverbed transparency option, non IANA registered option number */
		SCTPOPT_RVBD_TRPY =      78,
		/** Unknown option */
		SCTPOPT_Unknown =        255
	};


	// SCTP option lengths

	/** pcpp::PCPP_SCTPOPT_NOP length */
#define PCPP_SCTPOLEN_NOP            1
	/** pcpp::PCPP_SCTPOPT_EOL length */
#define PCPP_SCTPOLEN_EOL            1
	/** pcpp::SCTPOPT_MSS length */
#define PCPP_SCTPOLEN_MSS            4
	/** pcpp::PCPP_SCTPOPT_WINDOW length */
#define PCPP_SCTPOLEN_WINDOW         3
	/** pcpp::SCTPOPT_SACK_PERM length */
#define PCPP_SCTPOLEN_SACK_PERM      2
	/** pcpp::PCPP_SCTPOPT_SACK length */
#define PCPP_SCTPOLEN_SACK_MIN       2
	/** pcpp::SCTPOPT_ECHO length */
#define PCPP_SCTPOLEN_ECHO           6
	/** pcpp::SCTPOPT_ECHOREPLY length */
#define PCPP_SCTPOLEN_ECHOREPLY      6
	/** pcpp::PCPP_SCTPOPT_TIMESTAMP length */
#define PCPP_SCTPOLEN_TIMESTAMP     10
	/** pcpp::SCTPOPT_CC length */
#define PCPP_SCTPOLEN_CC             6
	/** pcpp::SCTPOPT_CCNEW length */
#define PCPP_SCTPOLEN_CCNEW          6
	/** pcpp::SCTPOPT_CCECHO length */
#define PCPP_SCTPOLEN_CCECHO         6
	/** pcpp::SCTPOPT_MD5 length */
#define PCPP_SCTPOLEN_MD5           18
	/** pcpp::SCTPOPT_MPSCTP length */
#define PCPP_SCTPOLEN_MPSCTP_MIN      8
	/** pcpp::SCTPOPT_SCPS length */
#define PCPP_SCTPOLEN_SCPS           4
	/** pcpp::SCTPOPT_SNACK length */
#define PCPP_SCTPOLEN_SNACK          6
	/** pcpp::SCTPOPT_RECBOUND length */
#define PCPP_SCTPOLEN_RECBOUND       2
	/** pcpp::SCTPOPT_CORREXP length */
#define PCPP_SCTPOLEN_CORREXP        2
	/** pcpp::SCTPOPT_QS length */
#define PCPP_SCTPOLEN_QS             8
	/** pcpp::SCTPOPT_USER_TO length */
#define PCPP_SCTPOLEN_USER_TO        4
	/** pcpp::SCTPOPT_RVBD_PROBE length */
#define PCPP_SCTPOLEN_RVBD_PROBE_MIN 3
	/** pcpp::SCTPOPT_RVBD_TRPY length */
#define PCPP_SCTPOLEN_RVBD_TRPY_MIN 16
	/** pcpp::SCTPOPT_EXP_FD and pcpp::SCTPOPT_EXP_FE length */
#define PCPP_SCTPOLEN_EXP_MIN        2


	/**
	 * @class SctpOption
	 * A wrapper class for SCTP options. This class does not create or modify SCTP option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class SctpOption : public TLVRecord
	{
	public:

		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the SCTP option raw data
		 */
		SctpOption(uint8_t* optionRawData) : TLVRecord(optionRawData) { }

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~SctpOption() { }

		/**
		 * @return SCTP option type casted as pcpp::SctpOptionType enum. If the data is null a value
		 * of ::SCTPOPT_Unknown is returned
		 */
		SctpOptionType getSctpOptionType() const
		{
			if (m_Data == NULL)
				return SCTPOPT_Unknown;

			return (SctpOptionType)m_Data->recordType;
		}

		// implement abstract methods

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


	/**
	 * @class SctpOptionBuilder
	 * A class for building SCTP option records. This builder receives the SCTP option parameters in its c'tor,
	 * builds the SCTP option raw buffer and provides a build() method to get a SctpOption object out of it
	 */
	class SctpOptionBuilder : public TLVRecordBuilder
	{

	public:

		/**
		 * An enum to describe NOP and EOL SCTP options. Used in one of this class's c'tors
		 */
		enum NopEolOptionTypes
		{
			/** NOP SCTP option */
			NOP,
			/** EOL SCTP option */
			EOL
		};

		/**
		 * A c'tor for building SCTP options which their value is a byte array. The SctpOption object can be later
		 * retrieved by calling build()
		 * @param[in] optionType SCTP option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in any way.
		 * @param[in] optionValueLen Option value length in bytes
		 */
		SctpOptionBuilder(SctpOptionType optionType, const uint8_t* optionValue, uint8_t optionValueLen) :
			TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen) {}

		/**
		 * A c'tor for building SCTP options which have a 1-byte value. The SctpOption object can be later retrieved
		 * by calling build()
		 * @param[in] optionType SCTP option type
		 * @param[in] optionValue A 1-byte option value
		 */
		SctpOptionBuilder(SctpOptionType optionType, uint8_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		/**
		 * A c'tor for building SCTP options which have a 2-byte value. The SctpOption object can be later retrieved
		 * by calling build()
		 * @param[in] optionType SCTP option type
		 * @param[in] optionValue A 2-byte option value
		 */
		SctpOptionBuilder(SctpOptionType optionType, uint16_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		/**
		 * A c'tor for building SCTP options which have a 4-byte value. The SctpOption object can be later retrieved
		 * by calling build()
		 * @param[in] optionType SCTP option type
		 * @param[in] optionValue A 4-byte option value
		 */
		SctpOptionBuilder(SctpOptionType optionType, uint32_t optionValue) :
			TLVRecordBuilder((uint8_t)optionType, optionValue) {}

		/**
		 * A c'tor for building SCTP NOP and EOL options. These option types are special in that they contain only 1 byte
		 * which is the SCTP option type (NOP or EOL). The SctpOption object can be later retrieved
		 * by calling build()
		 * @param[in] optionType An enum value indicating which option type to build (NOP or EOL)
		 */
		SctpOptionBuilder(NopEolOptionTypes optionType);

		/**
		 * Build the SctpOption object out of the parameters defined in the c'tor
		 * @return The SctpOption object
		 */
		SctpOption build() const;
	};


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

		/**
		 * A constructor that allocates a new SCTP header with source port and destination port and zero SCTP options
		 * @param[in] portSrc Source port
		 * @param[in] portDst Destination port
		 */
		SctpLayer(uint16_t portSrc, uint16_t portDst);

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
		 * @return An SctpOption object that contains the first option that matches this type, or logical NULL
		 * (SctpOption#isNull() == true) if no such option found
		 */
		SctpOption getSctpOption(SctpOptionType option) const;

		/**
		 * @return The first SCTP option in the packet. If the current layer contains no options the returned value will contain
		 * a logical NULL (SctpOption#isNull() == true)
		 */
		SctpOption getFirstSctpOption() const;

		/**
		 * Get the SCTP option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical NULL (SctpOption#isNull() == true)
		 * @param[in] sctpOption A SCTP option object that exists in the current layer
		 * @return A SctpOption object that contains the SCTP option data that comes next, or logical NULL if the given
		 * SCTP option: (1) was the last one; or (2) contains a logical NULL; or (3) doesn't belong to this packet
		 */
		SctpOption getNextSctpOption(SctpOption& sctpOption) const;

		/**
		 * @return The number of SCTP options in this layer
		 */
		size_t getSctpOptionCount() const;

		/**
		 * Add a new SCTP option at the end of the layer (after the last SCTP option)
		 * @param[in] optionBuilder A SctpOptionBuilder object that contains the SCTP option data to be added
		 * @return A SctpOption object that contains the newly added SCTP option data or logical NULL
		 * (SctpOption#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		SctpOption addSctpOption(const SctpOptionBuilder& optionBuilder);

		/**
		 * Add a new SCTP option after an existing one
		 * @param[in] optionBuilder A SctpOptionBuilder object that contains the requested SCTP option data to be added
		 * @param[in] prevOptionType The SCTP option which the newly added option should come after. This is an optional parameter which
		 * gets a default value of ::SCTPOPT_Unknown if omitted, which means the new option will be added as the first option in the layer
		 * @return A SctpOption object containing the newly added SCTP option data or logical NULL
		 * (SctpOption#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		SctpOption addSctpOptionAfter(const SctpOptionBuilder& optionBuilder, SctpOptionType prevOptionType = SCTPOPT_Unknown);

		/**
		 * Remove an existing SCTP option from the layer. SCTP option is found by type
		 * @param[in] optionType The SCTP option type to remove
		 * @return True if SCTP option was removed or false if type wasn't found or if removal failed (in each case a proper error
		 * will be written to log)
		 */
		bool removeSctpOption(SctpOptionType optionType);

		/**
		 * Remove all SCTP options in this layer
		 * @return True if all SCTP options were successfully removed or false if removal failed for some reason
		 * (a proper error will be written to log)
		 */
		bool removeAllSctpOptions();


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
		size_t getHeaderLen() const { return getSctpHeader()->dataOffset*4 ;}

		/**
		 * Calculate @ref sctphdr#headerChecksum field
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelTransportLayer; }

	private:

		TLVRecordReader<SctpOption> m_OptionReader;
		int m_NumOfTrailingBytes;

		void initLayer();
		uint8_t* getOptionsBasePtr() const { return m_Data + sizeof(sctphdr); }
		SctpOption addSctpOptionAt(const SctpOptionBuilder& optionBuilder, int offset);
		void adjustSctpOptionTrailer(size_t totalOptSize);
		void copyLayerData(const SctpLayer& other);
	};


	// implementation of inline methods

	bool SctpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		const sctphdr* hdr = reinterpret_cast<const sctphdr*>(data);
		return dataLen >= sizeof(sctphdr)
			&& hdr->dataOffset >= 5 /* the minimum SCTP header size */
			&& dataLen >= hdr->dataOffset * sizeof(uint32_t);
	}

} // namespace pcpp

#endif /* PACKETPP_SCTP_LAYER */
