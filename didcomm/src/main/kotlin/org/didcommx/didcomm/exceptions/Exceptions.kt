package org.didcommx.didcomm.exceptions

import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType

/**
 * The base class for all DIDComm exceptions.
 *
 * @param message - the detail message.
 * @param cause - the cause of this.
 */
open class DIDCommException(message: String, cause: Throwable? = null) : Throwable(message, cause)

/**
 * The base class for DIDComm exceptions about unsupported values.
 *
 * @param message - the detail message.
 */
open class DIDCommUnsupportedValueException(message: String, cause: Throwable? = null) : DIDCommException(message, cause)

/**
 * This exception SHOULD be raised if verification method type is not supported.
 *
 * @param type The verification method type.
 */
class UnsupportedVerificationMethodTypeException(type: VerificationMethodType) :
    DIDCommUnsupportedValueException("${type.name} verification method type is not supported")

/**
 * This exception SHOULD be raised if material format is not supported for verification method type.
 *
 * @param format The verification material format.
 * @param type The verification method type.
 */
class UnsupportedVerificationMethodMaterialFormatException(
    format: VerificationMaterialFormat,
    type: VerificationMethodType
) : DIDCommUnsupportedValueException(
    "${format.name} material format is not supported for ${type.name} verification method type"
)

/**
 * This exception SHOULD be raised if secret type is not supported.
 *
 * @param type The secret type.
 */
class UnsupportedSecretTypeException(type: VerificationMethodType) :
    DIDCommUnsupportedValueException("${type.name} secret type is not supported")

/**
 * This exception SHOULD be raised if material format is not supported for secret type.
 *
 * @param format The verification material format.
 * @param type The secret type.
 */
class UnsupportedSecretMaterialFormatException(
    format: VerificationMaterialFormat,
    type: VerificationMethodType
) : DIDCommUnsupportedValueException("${format.name} material format is not supported for ${type.name} secret type")

/**
 * This exception SHOULD be raised if curve is not supported.
 *
 * @param curve The curve.
 */
class UnsupportedCurveException(curve: String) : DIDCommUnsupportedValueException("The curve $curve is not supported")

/**
 * This exception SHOULD be raised if JWK is not supported.
 * For example, if JWK is RSA Key.
 *
 * @param jwk The JWK.
 */
class UnsupportedJWKException(jwk: String) : DIDCommUnsupportedValueException("The JWK $jwk is not supported")

/**
 * This exception SHOULD be raises if algorithm is not supported.
 *
 * @param alg JWA
 */
class UnsupportedAlgorithm(alg: String, cause: Throwable? = null) : DIDCommUnsupportedValueException("The algorithm $alg is not supported", cause)

/**
 * The base class for DID Doc exceptions
 *
 * @param message - the detail message.
 */
open class DIDDocException(message: String) : DIDCommException(message)

/**
 * This exception SHOULD be raised if DID Doc can not be resolved.
 *
 * @param did The did.
 */
class DIDDocNotResolvedException(did: String) : DIDDocException("The DID Doc '$did' not resolved")

/**
 * This exception SHOULD be raised if DID URL not founded.
 *
 * @param didUrl The did url.
 */
class DIDUrlNotFoundException(didUrl: String, did: String) : DIDDocException("The DID URL '$didUrl' not found in DID Doc '$did'")

/**
 * This exception SHOULD be raised if Secret can not be found.
 *
 * @param kid The Key Identifier.
 */
class SecretNotFoundException(kid: String) : DIDCommException("The Secret '$kid' not found")

/**
 * This exception SHOULD be raised if argument is illegal.
 *
 * @param argument illegal argument.
 */
class DIDCommIllegalArgumentException(argument: String) : DIDCommException("The argument $argument is not valid")

/**
 * This exception SHOULD be raised if DIDCommService is invalid.
 *
 * @param did The did.
 * @param msg Error.
 */
class DIDCommServiceException(did: String, msg: String) : DIDDocException("Invalid DIDCommService for DID Doc '$did': $msg")

/**
 * Signals that packed message is malformed.
 *
 * @param message - the detail message.
 * @param cause - the cause of this.
 */
class MalformedMessageException(message: String, cause: Throwable? = null) : DIDCommException(message, cause)

/**
 * Signals that crypto is incompatible
 *
 * @param message - the detail message.
 */
class IncompatibleCryptoException(message: String) : DIDCommException(message)
