import ArgumentParser
import Foundation
import MachO

@main
struct ProtoPrinter: ParsableCommand {
    @Argument(help: "The binary file to print conformances from")
    var target: String

    mutating func run() throws {
        // TODO: Better error handling
        let fileURL = URL(string: "file://\((target as NSString).expandingTildeInPath)")!
        let data64 = try Data(contentsOf: fileURL, options: .mappedIfSafe)

        // Access data via pointers for easier traversal
        data64.withUnsafeBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }

            let magicNumber = baseAddress.load(as: UInt32.self)

            let offset: Int
            let size: Int

            if magicNumber.bigEndian == FAT_MAGIC {
                // Protocols conformances should be the same. Grab the first architecture
                let entry = baseAddress
                    .advanced(by: MemoryLayout<fat_header>.size)
                    .assumingMemoryBound(to: fat_arch.self)

                offset = Int(entry.pointee.offset.bigEndian)
                size = Int(entry.pointee.size.bigEndian)
            } else {
                offset = 0
                size = bytes.count
            }

            let header = baseAddress
                .advanced(by: offset)
                .assumingMemoryBound(to: mach_header_64.self)

            guard header.pointee.magic == MH_MAGIC_64 else {
                print("Unexpected header magic number: 0x\(String(header.pointee.magic, radix: 16))")
                return
            }

            // Get the header for the protocol conformance section
            let sectionHeaderPtr = getSectionHeader(
                header: header,
                segmentName: "__TEXT",
                sectionName: "__swift5_proto"
            )
            guard let sectionHeader = sectionHeaderPtr?.pointee else { return }

            printConformances(
                in: sectionHeader,
                baseAddress: baseAddress.advanced(by: offset),
                maxAddress: baseAddress + offset + size
            )
        }
    }
}

extension ProtoPrinter {
    /// Get a section header by the name of the segment it's in and the name of the section itself
    ///
    /// - Parameters:
    ///   - header: Mach header for the binary being inspected
    ///   - segmentName: Name of the segment to search. e.g. "__TEXT"
    ///   - sectionName: Name of the section to find. e.g. "__swift5_proto"
    /// - Returns: A pointer to the section if it exists
    private func getSectionHeader(
        header: UnsafePointer<mach_header_64>,
        segmentName: String,
        sectionName: String
    ) -> UnsafePointer<section_64>? {
        // Load commands start immediately after mach header
        let commandStartPtr = header.offset(bytes: MemoryLayout<mach_header_64>.size, as: load_command.self)
        let segmentStride = MemoryLayout<segment_command_64>.stride

        for commandIndex in 0 ..< Int(header.pointee.ncmds) {
            let commandPtr = commandStartPtr.advanced(by: commandIndex)

            // TODO: Support `LC_SEGMENT` (32 bit)?
            if commandPtr.pointee.cmd == LC_SEGMENT_64 {
                // Rebind commandPtr to segment_command_64
                let segmentCommand = commandPtr.offset(bytes: 0, as: segment_command_64.self)

                // Only look at segments matching the desired segment name
                guard String(tuple: segmentCommand.pointee.segname) == segmentName else {
                    continue
                }

                // Loop through the sections in the segment
                let sectionsStartPtr = segmentCommand.offset(bytes: segmentStride, as: section_64.self)
                for sectionIndex in 0 ..< Int(segmentCommand.pointee.nsects) {
                    // Check if the section matches the desired section name
                    let sectionPtr = sectionsStartPtr.advanced(by: sectionIndex)
                    if String(tuple: sectionPtr.pointee.sectname) == sectionName {
                        return sectionPtr
                    }
                }
            }
        }
        return nil
    }

    private func printConformances(
        in sectionHeader: section_64,
        baseAddress: UnsafeRawPointer,
        maxAddress: UnsafeRawPointer
    ) {
        // Needed to loop over conformances
        let align = Int(pow(2, Double(sectionHeader.align)))
        let count = Int(sectionHeader.size) / align

        for index in 0 ..< count {
            // Find address of the actual conformance
            let conformanceAddress = baseAddress.advanced(by: Int(sectionHeader.offset) + index * align)
            let conformanceOffset = conformanceAddress.assumingMemoryBound(to: Int32.self).pointee

            // Address is relative to the location of address value itself
            let conformancePtr = conformanceAddress
                .advanced(by: Int(conformanceOffset))
                .assumingMemoryBound(to: ProtocolConformanceDescriptor.self)

            let conformance = conformancePtr.pointee

            let kind = conformance.flags.typeReferenceKind
            guard kind == .directTypeDescriptor || kind == .indirectTypeDescriptor else { continue }

            guard conformance.protocolWitnessTable != 0 else {
                // 🤷
                continue
            }

            let protocolPtr: UnsafePointer<ProtocolDescriptor>

            // Low bit in `protocolDescriptor` signifies an indirect pointer. Indirect pointers
            // resolve to a new address that's an absolute relative to the base address
            if conformance.protocolDescriptor & 1 == 1 {
                // Get rid of indirect signifier bit
                let localOffset = Int(conformance.protocolDescriptor & ~1)

                let absoluteOffset = conformancePtr
                    .offset(bytes: localOffset, as: UInt32.self)
                    .pointee

                protocolPtr = baseAddress
                    .advanced(by: Int(absoluteOffset))
                    .assumingMemoryBound(to: ProtocolDescriptor.self)
            } else {
                protocolPtr = conformancePtr.following(\.protocolDescriptor)
            }

            // Get pointer to type conforming to the protocol
            let typePtr: UnsafePointer<TargetContextDescriptor>
            switch kind {
            case .directTypeDescriptor:
                typePtr = conformancePtr.following(\.nominalTypeDescriptor)

            case .indirectTypeDescriptor:
                // Same idea as indirect protocol pointer above
                let localOffset = conformancePtr
                    .following(\.nominalTypeDescriptor, as: UInt32.self)
                    .pointee

                typePtr = baseAddress
                    .advanced(by: Int(localOffset))
                    .assumingMemoryBound(to: TargetContextDescriptor.self)

            case .directObjCClass, .indirectObjCClass:
                // TODO: Support Objective-C classes?
                continue
            }

            let typeNamePtr = typePtr.following(\.name, as: UInt8.self)
            let typeName: String

            if (baseAddress ..< maxAddress).contains(UnsafeRawPointer(typeNamePtr)) {
                typeName = typeNamePtr.asString()
            } else {
                typeName = "Type out of bounds"
            }

            let protocolNamePtr = protocolPtr.following(\.name, as: UInt8.self)
            let protocolName: String

            if (baseAddress ..< maxAddress).contains(UnsafeRawPointer(protocolNamePtr)) {
                protocolName = protocolNamePtr.asString()
            } else {
                protocolName = "Protocol out of bounds"
            }

            print("Type: \(typeName), Protocol: \(protocolName)")
            print("")
        }
    }
}

/// Types adapted from https://github.com/Azoy/Echo/

// MARK: - ProtocolConformanceDescriptor

struct ProtocolConformanceDescriptor {
    let protocolDescriptor: Int32
    var nominalTypeDescriptor: Int32
    let protocolWitnessTable: Int32
    let flags: Flags
}

extension ProtocolConformanceDescriptor {
    struct Flags {
        private let bits: UInt32

        /// Whether or not the conformance descriptor's witness table pattern is
        /// used as a pattern or if it's served as the real witness table. This is
        /// most likely true when the conformance is about a generic type and false
        /// when the conformance is about a non generic type. Please make sure to
        /// consult this flag beforehand though to make sure.
        var hasGenericWitnessTable: Bool {
            bits & (0x1 << 17) != 0
        }

        /// Whether or not this conformance has resilient witnesses.
        var hasResilientWitnesses: Bool {
            bits & (0x1 << 16) != 0
        }

        /// Whether or not this conformance is retroactive. A conformance is
        /// considered retroactive when it happens in a module that is not the
        /// module the protocol was defined in and not the module the type conforming
        /// was defined in.
        var isRetroactive: Bool {
            bits & (0x1 << 6) != 0
        }

        /// Whether or not this conformance was synthesized non-uniquely. This
        /// happens when an imported C structure or such defines a Swift conformance.
        var isSynthesizedNonUnique: Bool {
            bits & (0x1 << 7) != 0
        }

        /// The number of conditional requirements this conformance requires. This
        /// occurs with conditional conformance situations where a type only conforms
        /// if one/a few/all of its generic parameters conform to some protocol.
        /// Another example is a type conforming to some protocol if it has some
        /// same type requirement.
        var numConditionalRequirements: Int {
            Int(bits & (0xFF << 8)) >> 8
        }

        /// The type reference kind to the type that is conforming to some protocol
        /// in this conformance.
        var typeReferenceKind: TypeReferenceKind {
            TypeReferenceKind(rawValue: UInt16(bits & (0x7 << 3)) >> 3)!
        }
    }
}

/// The type of reference this is to some type.
enum TypeReferenceKind: UInt16 {
    /// This is a direct relative reference to the type's context descriptor.
    case directTypeDescriptor = 0x0

    /// This is an indirect relative reference to the type's context descriptor.
    case indirectTypeDescriptor = 0x1

    /// This is a direct relative reference to some Objective-C class metadata.
    case directObjCClass = 0x2

    /// This is an indirect relative reference to some Objective-C class metadata.
    case indirectObjCClass = 0x3
}

// MARK: - ProtocolDescriptor

struct ProtocolDescriptor {
    let flags: ContextDescriptorFlags
    let parent: Int32
    let name: Int32
    let numRequirementsInSignature: UInt32
    let numRequirements: UInt32
    let associatedTypeNames: Int32
}

public enum ContextDescriptorKind: Int {
    case module = 0
    case `extension` = 1
    case anonymous = 2
    case `protocol` = 3
    case opaqueType = 4
    case `class` = 16
    case `struct` = 17
    case `enum` = 18
}

/// The flags which describe a context descriptor.
public struct ContextDescriptorFlags {
    /// Flags as represented in bits.
    public let bits: UInt32

    /// The kind of context this descriptor is.
    public var kind: ContextDescriptorKind {
        return ContextDescriptorKind(rawValue: Int(bits) & 0x1F)!
    }

    /// Whether this context is "unique".
    public var isUnique: Bool {
        bits & 0x40 != 0
    }

    /// Whether or not this context is generic and has a generic context.
    public var isGeneric: Bool {
        bits & 0x80 != 0
    }

    /// The version number for this context descriptor.
    public var version: UInt8 {
        UInt8((bits >> 0x8) & 0xFF)
    }

    /// Whether the context has information about invertible protocols, which
    /// will show up as a trailing field in the context descriptor.
    var hasInvertibleProtocols: Bool {
        (bits & 0x20) != 0;
    }

    var kindSpecificFlags: UInt16 {
        UInt16((bits >> 0x10) & 0xFFFF)
    }
}

// MARK: - TargetContextDescriptor

struct TargetContextDescriptor {
    let flags: UInt32
    let parent: Int32
    let name: Int32
    let accessor: Int32
    let fields: FieldDescriptor
}

struct FieldDescriptor {
    let mangledTypeName: UInt32
    let superclass: UInt32
    let kind: UInt16
    let recordSize: UInt16
    let numFields: UInt32
}

extension UnsafePointer {
    /// Get a new UnsafePointer offset by a number of bytes that's bound to the expected destination type
    ///
    /// - Parameters:
    ///   - offset: How many bytes to offset the original pointer by
    ///   - destination: The type to rebind the pointer to
    func offset<T>(bytes offset: Int, as destination: T.Type = T.self) -> UnsafePointer<T> {
        UnsafeRawPointer(self)
            .advanced(by: offset)
            .assumingMemoryBound(to: destination)
    }

    /// Get a new UnsafePointer by following an offset property that's bound to the expected destination type
    ///
    /// - Parameters:
    ///   - reference: Key path to the reference property to follow
    ///   - destination: The type to rebind the pointer to
    func following<T>(_ reference: KeyPath<Pointee, Int32>, as destination: T.Type = T.self) -> UnsafePointer<T> {
        // How far into the type is the property + the value of the property
        let offset = MemoryLayout<Pointee>.offset(of: reference)! + Int(pointee[keyPath: reference])
        return self.offset(bytes: offset, as: destination)
    }
}

extension UnsafePointer<UInt8> {
    /// Convert an unsafe pointer to `UInt8` to a `String`
    func asString() -> String { String(cString: self) }
}

extension String {
    /// Create a `String` from a tuple of characters
    init(tuple: (CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar)) {
        // Get all of the characters
        var cString: [CChar] = Mirror(reflecting: tuple).children.map { $0.value as! CChar }
        // Append a null character just in case
        cString.append(0)

        self.init(cString: cString)
    }
}
