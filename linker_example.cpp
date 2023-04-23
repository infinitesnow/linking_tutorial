#include <iostream> // std::cout
#include <iomanip> // std::setfill, std::setw
#include <cstddef> // size_t
#include <stdexcept> // std::invalid_argument 

/* Define an array of bytes. The "extern" modifier tells the compiler to not assign any value to this.
 * Think of the linker as the Python importer, it's the thing that links functions to their implementation.
 * In C++ you can declare that a function exists, but it's implemented by someone else.
 * "extern" will ask the linker to fill in this symbol. */
extern char _binary_random_data_bin_start[];
extern char _binary_format_data_bin_start[];

int main(
	int argc /* number of cli arguments, "argument count" */,
	char* argv[] /* vector of pointers to arguments as char arrays, "argument vector" */ )
{
	if(argc <=1 )
	{
		throw std::invalid_argument("Usage: ./test <num_bytes>");
	}

	/* Get first command line argument, argv[1]; 
	 * argv[0] is always the program name in Unix systems */
	size_t num_bytes = std::stoull(argv[1]); 


	size_t line_size = _binary_format_data_bin_start[0];
	/* See below for std::cout */
	std::cout << "_binary_random_data_bin_start is at address " 
		<< std::hex << static_cast<void*>(_binary_random_data_bin_start)
		<< std::endl;
	std::cout << "_binary_format_data_bin_start is at address " 
		<< std::hex << static_cast<void*>(_binary_format_data_bin_start)
		<< std::endl;
	std::cout << "Printing " << line_size << " bytes per line." << std::hex << std::endl;

	size_t print_cnt = 0; /* Count printed characters */
	bool first_line = true;
	for (size_t array_idx = 0; array_idx < num_bytes; array_idx++)
	{
		/* You can rewrite part of the line below as:
		 * 
		 * std::cout.operator<<(std::hex).operator<<( (size_t) binddata[i] ).operator<<(std::endl);
		 *
		 * operator<< returns the object it is called on, similar to what happens in JavaScript. 
		 * It's called "operator chaining".
		 * Note that some overloads are defined outside the class, in order to print a string literal
		 * for example:
		 *
		 * operator<< ( std::cout, "hello" );
		 *
		 * std::setfill sets the padding character
		 * std::setw sets the space occupied by the entry
		 * std::hex modifies the stream to format what future input to hexadecimal
		 * std::endl is a portable end of line terminator. It's different across Windows and Linux
		 *
		 * This kinda makes sense overall, but yes, streams in C++ are kinda cursed.
		 * If you ever write production quality C++, use libfmt. 
		 */
		std::cout 
			<< std::setfill('0')
			<< std::setw(2)
			<< std::hex /* parse to hex */ 
			<< static_cast<size_t>(_binary_random_data_bin_start[array_idx] & 0xFF) /* Don't interpret it as ASCII */ 
			<< " ";
		/* Align with hexdump output. ++print_cnt is a combined increment-use. 
		 * print_cnt++ would be use-increment. */
		if (++print_cnt % line_size == 0 && !first_line )
		{
			std::cout << std::endl /* Portable newline */;
		}
		first_line = false;
	}
}
