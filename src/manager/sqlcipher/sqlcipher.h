/*
** 2001 September 15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This header file defines the interface that the SQLite library
** presents to client programs.  If a C-function, structure, datatype,
** or constant definition does not appear in this file, then it is
** not a published API of SQLite, is subject to change without
** notice, and should not be referenced by programs that use SQLite.
**
** Some of the definitions that are in this file are marked as
** "experimental".  Experimental interfaces are normally new
** features recently added to SQLite.  We do not anticipate changes
** to experimental interfaces but reserve the right to make minor changes
** if experience from use "in the wild" suggest such changes are prudent.
**
** The official C-language API documentation for SQLite is derived
** from comments in this file.  This file is the authoritative source
** on how SQLite interfaces are suppose to operate.
**
** The name of this file under configuration management is "sqlcipher.h.in".
** The makefile makes some minor changes to this file (such as inserting
** the version number) and changes its name to "sqlcipher3.h" as
** part of the build process.
*/
#ifndef _SQLCIPHER3_H_
#define _SQLCIPHER3_H_
#include <stdarg.h>     /* Needed for the definition of va_list */

/*
** Make sure we can call this stuff from C++.
*/
#ifdef __cplusplus
extern "C" {
#endif


/*
** Add the ability to override 'extern'
*/
#ifndef SQLCIPHER_EXTERN
# define SQLCIPHER_EXTERN extern
#endif

#ifndef SQLCIPHER_API
# define SQLCIPHER_API
#endif


/*
** These no-op macros are used in front of interfaces to mark those
** interfaces as either deprecated or experimental.  New applications
** should not use deprecated interfaces - they are support for backwards
** compatibility only.  Application writers should be aware that
** experimental interfaces are subject to change in point releases.
**
** These macros used to resolve to various kinds of compiler magic that
** would generate warning messages when they were used.  But that
** compiler magic ended up generating such a flurry of bug reports
** that we have taken it all out and gone back to using simple
** noop macros.
*/
#define SQLCIPHER_DEPRECATED
#define SQLCIPHER_EXPERIMENTAL

/*
** Ensure these symbols were not defined by some previous header file.
*/
#ifdef SQLCIPHER_VERSION
# undef SQLCIPHER_VERSION
#endif
#ifdef SQLCIPHER_VERSION_NUMBER
# undef SQLCIPHER_VERSION_NUMBER
#endif

/*
** CAPI3REF: Compile-Time Library Version Numbers
**
** ^(The [SQLCIPHER_VERSION] C preprocessor macro in the sqlcipher3.h header
** evaluates to a string literal that is the SQLite version in the
** format "X.Y.Z" where X is the major version number (always 3 for
** SQLite3) and Y is the minor version number and Z is the release number.)^
** ^(The [SQLCIPHER_VERSION_NUMBER] C preprocessor macro resolves to an integer
** with the value (X*1000000 + Y*1000 + Z) where X, Y, and Z are the same
** numbers used in [SQLCIPHER_VERSION].)^
** The SQLCIPHER_VERSION_NUMBER for any given release of SQLite will also
** be larger than the release from which it is derived.  Either Y will
** be held constant and Z will be incremented or else Y will be incremented
** and Z will be reset to zero.
**
** Since version 3.6.18, SQLite source code has been stored in the
** <a href="http://www.fossil-scm.org/">Fossil configuration management
** system</a>.  ^The SQLCIPHER_SOURCE_ID macro evaluates to
** a string which identifies a particular check-in of SQLite
** within its configuration management system.  ^The SQLCIPHER_SOURCE_ID
** string contains the date and time of the check-in (UTC) and an SHA1
** hash of the entire source tree.
**
** See also: [sqlcipher3_libversion()],
** [sqlcipher3_libversion_number()], [sqlcipher3_sourceid()],
** [sqlcipher_version()] and [sqlcipher_source_id()].
*/
#define SQLCIPHER_VERSION        "3.7.9"
#define SQLCIPHER_VERSION_NUMBER 3007009
#define SQLCIPHER_SOURCE_ID      "2011-11-01 00:52:41 c7c6050ef060877ebe77b41d959e9df13f8c9b5e"

/*
** CAPI3REF: Run-Time Library Version Numbers
** KEYWORDS: sqlcipher3_version, sqlcipher3_sourceid
**
** These interfaces provide the same information as the [SQLCIPHER_VERSION],
** [SQLCIPHER_VERSION_NUMBER], and [SQLCIPHER_SOURCE_ID] C preprocessor macros
** but are associated with the library instead of the header file.  ^(Cautious
** programmers might include assert() statements in their application to
** verify that values returned by these interfaces match the macros in
** the header, and thus insure that the application is
** compiled with matching library and header files.
**
** <blockquote><pre>
** assert( sqlcipher3_libversion_number()==SQLCIPHER_VERSION_NUMBER );
** assert( strcmp(sqlcipher3_sourceid(),SQLCIPHER_SOURCE_ID)==0 );
** assert( strcmp(sqlcipher3_libversion(),SQLCIPHER_VERSION)==0 );
** </pre></blockquote>)^
**
** ^The sqlcipher3_version[] string constant contains the text of [SQLCIPHER_VERSION]
** macro.  ^The sqlcipher3_libversion() function returns a pointer to the
** to the sqlcipher3_version[] string constant.  The sqlcipher3_libversion()
** function is provided for use in DLLs since DLL users usually do not have
** direct access to string constants within the DLL.  ^The
** sqlcipher3_libversion_number() function returns an integer equal to
** [SQLCIPHER_VERSION_NUMBER].  ^The sqlcipher3_sourceid() function returns 
** a pointer to a string constant whose value is the same as the 
** [SQLCIPHER_SOURCE_ID] C preprocessor macro.
**
** See also: [sqlcipher_version()] and [sqlcipher_source_id()].
*/
SQLCIPHER_API SQLCIPHER_EXTERN const char sqlcipher3_version[];
SQLCIPHER_API const char *sqlcipher3_libversion(void);
SQLCIPHER_API const char *sqlcipher3_sourceid(void);
SQLCIPHER_API int sqlcipher3_libversion_number(void);

/*
** CAPI3REF: Run-Time Library Compilation Options Diagnostics
**
** ^The sqlcipher3_compileoption_used() function returns 0 or 1 
** indicating whether the specified option was defined at 
** compile time.  ^The SQLCIPHER_ prefix may be omitted from the 
** option name passed to sqlcipher3_compileoption_used().  
**
** ^The sqlcipher3_compileoption_get() function allows iterating
** over the list of options that were defined at compile time by
** returning the N-th compile time option string.  ^If N is out of range,
** sqlcipher3_compileoption_get() returns a NULL pointer.  ^The SQLCIPHER_ 
** prefix is omitted from any strings returned by 
** sqlcipher3_compileoption_get().
**
** ^Support for the diagnostic functions sqlcipher3_compileoption_used()
** and sqlcipher3_compileoption_get() may be omitted by specifying the 
** [SQLCIPHER_OMIT_COMPILEOPTION_DIAGS] option at compile time.
**
** See also: SQL functions [sqlcipher_compileoption_used()] and
** [sqlcipher_compileoption_get()] and the [compile_options pragma].
*/
#ifndef SQLCIPHER_OMIT_COMPILEOPTION_DIAGS
SQLCIPHER_API int sqlcipher3_compileoption_used(const char *zOptName);
SQLCIPHER_API const char *sqlcipher3_compileoption_get(int N);
#endif

/*
** CAPI3REF: Test To See If The Library Is Threadsafe
**
** ^The sqlcipher3_threadsafe() function returns zero if and only if
** SQLite was compiled mutexing code omitted due to the
** [SQLCIPHER_THREADSAFE] compile-time option being set to 0.
**
** SQLite can be compiled with or without mutexes.  When
** the [SQLCIPHER_THREADSAFE] C preprocessor macro is 1 or 2, mutexes
** are enabled and SQLite is threadsafe.  When the
** [SQLCIPHER_THREADSAFE] macro is 0, 
** the mutexes are omitted.  Without the mutexes, it is not safe
** to use SQLite concurrently from more than one thread.
**
** Enabling mutexes incurs a measurable performance penalty.
** So if speed is of utmost importance, it makes sense to disable
** the mutexes.  But for maximum safety, mutexes should be enabled.
** ^The default behavior is for mutexes to be enabled.
**
** This interface can be used by an application to make sure that the
** version of SQLite that it is linking against was compiled with
** the desired setting of the [SQLCIPHER_THREADSAFE] macro.
**
** This interface only reports on the compile-time mutex setting
** of the [SQLCIPHER_THREADSAFE] flag.  If SQLite is compiled with
** SQLCIPHER_THREADSAFE=1 or =2 then mutexes are enabled by default but
** can be fully or partially disabled using a call to [sqlcipher3_config()]
** with the verbs [SQLCIPHER_CONFIG_SINGLETHREAD], [SQLCIPHER_CONFIG_MULTITHREAD],
** or [SQLCIPHER_CONFIG_MUTEX].  ^(The return value of the
** sqlcipher3_threadsafe() function shows only the compile-time setting of
** thread safety, not any run-time changes to that setting made by
** sqlcipher3_config(). In other words, the return value from sqlcipher3_threadsafe()
** is unchanged by calls to sqlcipher3_config().)^
**
** See the [threading mode] documentation for additional information.
*/
SQLCIPHER_API int sqlcipher3_threadsafe(void);

/*
** CAPI3REF: Database Connection Handle
** KEYWORDS: {database connection} {database connections}
**
** Each open SQLite database is represented by a pointer to an instance of
** the opaque structure named "sqlcipher3".  It is useful to think of an sqlcipher3
** pointer as an object.  The [sqlcipher3_open()], [sqlcipher3_open16()], and
** [sqlcipher3_open_v2()] interfaces are its constructors, and [sqlcipher3_close()]
** is its destructor.  There are many other interfaces (such as
** [sqlcipher3_prepare_v2()], [sqlcipher3_create_function()], and
** [sqlcipher3_busy_timeout()] to name but three) that are methods on an
** sqlcipher3 object.
*/
typedef struct sqlcipher3 sqlcipher3;

/*
** CAPI3REF: 64-Bit Integer Types
** KEYWORDS: sqlcipher_int64 sqlcipher_uint64
**
** Because there is no cross-platform way to specify 64-bit integer types
** SQLite includes typedefs for 64-bit signed and unsigned integers.
**
** The sqlcipher3_int64 and sqlcipher3_uint64 are the preferred type definitions.
** The sqlcipher_int64 and sqlcipher_uint64 types are supported for backwards
** compatibility only.
**
** ^The sqlcipher3_int64 and sqlcipher_int64 types can store integer values
** between -9223372036854775808 and +9223372036854775807 inclusive.  ^The
** sqlcipher3_uint64 and sqlcipher_uint64 types can store integer values 
** between 0 and +18446744073709551615 inclusive.
*/
#ifdef SQLCIPHER_INT64_TYPE
  typedef SQLCIPHER_INT64_TYPE sqlcipher_int64;
  typedef unsigned SQLCIPHER_INT64_TYPE sqlcipher_uint64;
#elif defined(_MSC_VER) || defined(__BORLANDC__)
  typedef __int64 sqlcipher_int64;
  typedef unsigned __int64 sqlcipher_uint64;
#else
  typedef long long int sqlcipher_int64;
  typedef unsigned long long int sqlcipher_uint64;
#endif
typedef sqlcipher_int64 sqlcipher3_int64;
typedef sqlcipher_uint64 sqlcipher3_uint64;

/*
** If compiling for a processor that lacks floating point support,
** substitute integer for floating-point.
*/
#ifdef SQLCIPHER_OMIT_FLOATING_POINT
# define double sqlcipher3_int64
#endif

/*
** CAPI3REF: Closing A Database Connection
**
** ^The sqlcipher3_close() routine is the destructor for the [sqlcipher3] object.
** ^Calls to sqlcipher3_close() return SQLCIPHER_OK if the [sqlcipher3] object is
** successfully destroyed and all associated resources are deallocated.
**
** Applications must [sqlcipher3_finalize | finalize] all [prepared statements]
** and [sqlcipher3_blob_close | close] all [BLOB handles] associated with
** the [sqlcipher3] object prior to attempting to close the object.  ^If
** sqlcipher3_close() is called on a [database connection] that still has
** outstanding [prepared statements] or [BLOB handles], then it returns
** SQLCIPHER_BUSY.
**
** ^If [sqlcipher3_close()] is invoked while a transaction is open,
** the transaction is automatically rolled back.
**
** The C parameter to [sqlcipher3_close(C)] must be either a NULL
** pointer or an [sqlcipher3] object pointer obtained
** from [sqlcipher3_open()], [sqlcipher3_open16()], or
** [sqlcipher3_open_v2()], and not previously closed.
** ^Calling sqlcipher3_close() with a NULL pointer argument is a 
** harmless no-op.
*/
SQLCIPHER_API int sqlcipher3_close(sqlcipher3 *);

/*
** The type for a callback function.
** This is legacy and deprecated.  It is included for historical
** compatibility and is not documented.
*/
typedef int (*sqlcipher3_callback)(void*,int,char**, char**);

/*
** CAPI3REF: One-Step Query Execution Interface
**
** The sqlcipher3_exec() interface is a convenience wrapper around
** [sqlcipher3_prepare_v2()], [sqlcipher3_step()], and [sqlcipher3_finalize()],
** that allows an application to run multiple statements of SQL
** without having to use a lot of C code. 
**
** ^The sqlcipher3_exec() interface runs zero or more UTF-8 encoded,
** semicolon-separate SQL statements passed into its 2nd argument,
** in the context of the [database connection] passed in as its 1st
** argument.  ^If the callback function of the 3rd argument to
** sqlcipher3_exec() is not NULL, then it is invoked for each result row
** coming out of the evaluated SQL statements.  ^The 4th argument to
** sqlcipher3_exec() is relayed through to the 1st argument of each
** callback invocation.  ^If the callback pointer to sqlcipher3_exec()
** is NULL, then no callback is ever invoked and result rows are
** ignored.
**
** ^If an error occurs while evaluating the SQL statements passed into
** sqlcipher3_exec(), then execution of the current statement stops and
** subsequent statements are skipped.  ^If the 5th parameter to sqlcipher3_exec()
** is not NULL then any error message is written into memory obtained
** from [sqlcipher3_malloc()] and passed back through the 5th parameter.
** To avoid memory leaks, the application should invoke [sqlcipher3_free()]
** on error message strings returned through the 5th parameter of
** of sqlcipher3_exec() after the error message string is no longer needed.
** ^If the 5th parameter to sqlcipher3_exec() is not NULL and no errors
** occur, then sqlcipher3_exec() sets the pointer in its 5th parameter to
** NULL before returning.
**
** ^If an sqlcipher3_exec() callback returns non-zero, the sqlcipher3_exec()
** routine returns SQLCIPHER_ABORT without invoking the callback again and
** without running any subsequent SQL statements.
**
** ^The 2nd argument to the sqlcipher3_exec() callback function is the
** number of columns in the result.  ^The 3rd argument to the sqlcipher3_exec()
** callback is an array of pointers to strings obtained as if from
** [sqlcipher3_column_text()], one for each column.  ^If an element of a
** result row is NULL then the corresponding string pointer for the
** sqlcipher3_exec() callback is a NULL pointer.  ^The 4th argument to the
** sqlcipher3_exec() callback is an array of pointers to strings where each
** entry represents the name of corresponding result column as obtained
** from [sqlcipher3_column_name()].
**
** ^If the 2nd parameter to sqlcipher3_exec() is a NULL pointer, a pointer
** to an empty string, or a pointer that contains only whitespace and/or 
** SQL comments, then no SQL statements are evaluated and the database
** is not changed.
**
** Restrictions:
**
** <ul>
** <li> The application must insure that the 1st parameter to sqlcipher3_exec()
**      is a valid and open [database connection].
** <li> The application must not close [database connection] specified by
**      the 1st parameter to sqlcipher3_exec() while sqlcipher3_exec() is running.
** <li> The application must not modify the SQL statement text passed into
**      the 2nd parameter of sqlcipher3_exec() while sqlcipher3_exec() is running.
** </ul>
*/
SQLCIPHER_API int sqlcipher3_exec(
  sqlcipher3*,                                  /* An open database */
  const char *sql,                           /* SQL to be evaluated */
  int (*callback)(void*,int,char**,char**),  /* Callback function */
  void *,                                    /* 1st argument to callback */
  char **errmsg                              /* Error msg written here */
);

/*
** CAPI3REF: Result Codes
** KEYWORDS: SQLCIPHER_OK {error code} {error codes}
** KEYWORDS: {result code} {result codes}
**
** Many SQLite functions return an integer result code from the set shown
** here in order to indicates success or failure.
**
** New error codes may be added in future versions of SQLite.
**
** See also: [SQLCIPHER_IOERR_READ | extended result codes],
** [sqlcipher3_vtab_on_conflict()] [SQLCIPHER_ROLLBACK | result codes].
*/
#define SQLCIPHER_OK           0   /* Successful result */
/* beginning-of-error-codes */
#define SQLCIPHER_ERROR        1   /* SQL error or missing database */
#define SQLCIPHER_INTERNAL     2   /* Internal logic error in SQLite */
#define SQLCIPHER_PERM         3   /* Access permission denied */
#define SQLCIPHER_ABORT        4   /* Callback routine requested an abort */
#define SQLCIPHER_BUSY         5   /* The database file is locked */
#define SQLCIPHER_LOCKED       6   /* A table in the database is locked */
#define SQLCIPHER_NOMEM        7   /* A malloc() failed */
#define SQLCIPHER_READONLY     8   /* Attempt to write a readonly database */
#define SQLCIPHER_INTERRUPT    9   /* Operation terminated by sqlcipher3_interrupt()*/
#define SQLCIPHER_IOERR       10   /* Some kind of disk I/O error occurred */
#define SQLCIPHER_CORRUPT     11   /* The database disk image is malformed */
#define SQLCIPHER_NOTFOUND    12   /* Unknown opcode in sqlcipher3_file_control() */
#define SQLCIPHER_FULL        13   /* Insertion failed because database is full */
#define SQLCIPHER_CANTOPEN    14   /* Unable to open the database file */
#define SQLCIPHER_PROTOCOL    15   /* Database lock protocol error */
#define SQLCIPHER_EMPTY       16   /* Database is empty */
#define SQLCIPHER_SCHEMA      17   /* The database schema changed */
#define SQLCIPHER_TOOBIG      18   /* String or BLOB exceeds size limit */
#define SQLCIPHER_CONSTRAINT  19   /* Abort due to constraint violation */
#define SQLCIPHER_MISMATCH    20   /* Data type mismatch */
#define SQLCIPHER_MISUSE      21   /* Library used incorrectly */
#define SQLCIPHER_NOLFS       22   /* Uses OS features not supported on host */
#define SQLCIPHER_AUTH        23   /* Authorization denied */
#define SQLCIPHER_FORMAT      24   /* Auxiliary database format error */
#define SQLCIPHER_RANGE       25   /* 2nd parameter to sqlcipher3_bind out of range */
#define SQLCIPHER_NOTADB      26   /* File opened that is not a database file */
#define SQLCIPHER_ROW         100  /* sqlcipher3_step() has another row ready */
#define SQLCIPHER_DONE        101  /* sqlcipher3_step() has finished executing */
/* end-of-error-codes */

/*
** CAPI3REF: Extended Result Codes
** KEYWORDS: {extended error code} {extended error codes}
** KEYWORDS: {extended result code} {extended result codes}
**
** In its default configuration, SQLite API routines return one of 26 integer
** [SQLCIPHER_OK | result codes].  However, experience has shown that many of
** these result codes are too coarse-grained.  They do not provide as
** much information about problems as programmers might like.  In an effort to
** address this, newer versions of SQLite (version 3.3.8 and later) include
** support for additional result codes that provide more detailed information
** about errors. The extended result codes are enabled or disabled
** on a per database connection basis using the
** [sqlcipher3_extended_result_codes()] API.
**
** Some of the available extended result codes are listed here.
** One may expect the number of extended result codes will be expand
** over time.  Software that uses extended result codes should expect
** to see new result codes in future releases of SQLite.
**
** The SQLCIPHER_OK result code will never be extended.  It will always
** be exactly zero.
*/
#define SQLCIPHER_IOERR_READ              (SQLCIPHER_IOERR | (1<<8))
#define SQLCIPHER_IOERR_SHORT_READ        (SQLCIPHER_IOERR | (2<<8))
#define SQLCIPHER_IOERR_WRITE             (SQLCIPHER_IOERR | (3<<8))
#define SQLCIPHER_IOERR_FSYNC             (SQLCIPHER_IOERR | (4<<8))
#define SQLCIPHER_IOERR_DIR_FSYNC         (SQLCIPHER_IOERR | (5<<8))
#define SQLCIPHER_IOERR_TRUNCATE          (SQLCIPHER_IOERR | (6<<8))
#define SQLCIPHER_IOERR_FSTAT             (SQLCIPHER_IOERR | (7<<8))
#define SQLCIPHER_IOERR_UNLOCK            (SQLCIPHER_IOERR | (8<<8))
#define SQLCIPHER_IOERR_RDLOCK            (SQLCIPHER_IOERR | (9<<8))
#define SQLCIPHER_IOERR_DELETE            (SQLCIPHER_IOERR | (10<<8))
#define SQLCIPHER_IOERR_BLOCKED           (SQLCIPHER_IOERR | (11<<8))
#define SQLCIPHER_IOERR_NOMEM             (SQLCIPHER_IOERR | (12<<8))
#define SQLCIPHER_IOERR_ACCESS            (SQLCIPHER_IOERR | (13<<8))
#define SQLCIPHER_IOERR_CHECKRESERVEDLOCK (SQLCIPHER_IOERR | (14<<8))
#define SQLCIPHER_IOERR_LOCK              (SQLCIPHER_IOERR | (15<<8))
#define SQLCIPHER_IOERR_CLOSE             (SQLCIPHER_IOERR | (16<<8))
#define SQLCIPHER_IOERR_DIR_CLOSE         (SQLCIPHER_IOERR | (17<<8))
#define SQLCIPHER_IOERR_SHMOPEN           (SQLCIPHER_IOERR | (18<<8))
#define SQLCIPHER_IOERR_SHMSIZE           (SQLCIPHER_IOERR | (19<<8))
#define SQLCIPHER_IOERR_SHMLOCK           (SQLCIPHER_IOERR | (20<<8))
#define SQLCIPHER_IOERR_SHMMAP            (SQLCIPHER_IOERR | (21<<8))
#define SQLCIPHER_IOERR_SEEK              (SQLCIPHER_IOERR | (22<<8))
#define SQLCIPHER_LOCKED_SHAREDCACHE      (SQLCIPHER_LOCKED |  (1<<8))
#define SQLCIPHER_BUSY_RECOVERY           (SQLCIPHER_BUSY   |  (1<<8))
#define SQLCIPHER_CANTOPEN_NOTEMPDIR      (SQLCIPHER_CANTOPEN | (1<<8))
#define SQLCIPHER_CORRUPT_VTAB            (SQLCIPHER_CORRUPT | (1<<8))
#define SQLCIPHER_READONLY_RECOVERY       (SQLCIPHER_READONLY | (1<<8))
#define SQLCIPHER_READONLY_CANTLOCK       (SQLCIPHER_READONLY | (2<<8))

/*
** CAPI3REF: Flags For File Open Operations
**
** These bit values are intended for use in the
** 3rd parameter to the [sqlcipher3_open_v2()] interface and
** in the 4th parameter to the [sqlcipher3_vfs.xOpen] method.
*/
#define SQLCIPHER_OPEN_READONLY         0x00000001  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_READWRITE        0x00000002  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_CREATE           0x00000004  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_DELETEONCLOSE    0x00000008  /* VFS only */
#define SQLCIPHER_OPEN_EXCLUSIVE        0x00000010  /* VFS only */
#define SQLCIPHER_OPEN_AUTOPROXY        0x00000020  /* VFS only */
#define SQLCIPHER_OPEN_URI              0x00000040  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_MAIN_DB          0x00000100  /* VFS only */
#define SQLCIPHER_OPEN_TEMP_DB          0x00000200  /* VFS only */
#define SQLCIPHER_OPEN_TRANSIENT_DB     0x00000400  /* VFS only */
#define SQLCIPHER_OPEN_MAIN_JOURNAL     0x00000800  /* VFS only */
#define SQLCIPHER_OPEN_TEMP_JOURNAL     0x00001000  /* VFS only */
#define SQLCIPHER_OPEN_SUBJOURNAL       0x00002000  /* VFS only */
#define SQLCIPHER_OPEN_MASTER_JOURNAL   0x00004000  /* VFS only */
#define SQLCIPHER_OPEN_NOMUTEX          0x00008000  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_FULLMUTEX        0x00010000  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_SHAREDCACHE      0x00020000  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_PRIVATECACHE     0x00040000  /* Ok for sqlcipher3_open_v2() */
#define SQLCIPHER_OPEN_WAL              0x00080000  /* VFS only */

/* Reserved:                         0x00F00000 */

/*
** CAPI3REF: Device Characteristics
**
** The xDeviceCharacteristics method of the [sqlcipher3_io_methods]
** object returns an integer which is a vector of the these
** bit values expressing I/O characteristics of the mass storage
** device that holds the file that the [sqlcipher3_io_methods]
** refers to.
**
** The SQLCIPHER_IOCAP_ATOMIC property means that all writes of
** any size are atomic.  The SQLCIPHER_IOCAP_ATOMICnnn values
** mean that writes of blocks that are nnn bytes in size and
** are aligned to an address which is an integer multiple of
** nnn are atomic.  The SQLCIPHER_IOCAP_SAFE_APPEND value means
** that when data is appended to a file, the data is appended
** first then the size of the file is extended, never the other
** way around.  The SQLCIPHER_IOCAP_SEQUENTIAL property means that
** information is written to disk in the same order as calls
** to xWrite().
*/
#define SQLCIPHER_IOCAP_ATOMIC                 0x00000001
#define SQLCIPHER_IOCAP_ATOMIC512              0x00000002
#define SQLCIPHER_IOCAP_ATOMIC1K               0x00000004
#define SQLCIPHER_IOCAP_ATOMIC2K               0x00000008
#define SQLCIPHER_IOCAP_ATOMIC4K               0x00000010
#define SQLCIPHER_IOCAP_ATOMIC8K               0x00000020
#define SQLCIPHER_IOCAP_ATOMIC16K              0x00000040
#define SQLCIPHER_IOCAP_ATOMIC32K              0x00000080
#define SQLCIPHER_IOCAP_ATOMIC64K              0x00000100
#define SQLCIPHER_IOCAP_SAFE_APPEND            0x00000200
#define SQLCIPHER_IOCAP_SEQUENTIAL             0x00000400
#define SQLCIPHER_IOCAP_UNDELETABLE_WHEN_OPEN  0x00000800

/*
** CAPI3REF: File Locking Levels
**
** SQLite uses one of these integer values as the second
** argument to calls it makes to the xLock() and xUnlock() methods
** of an [sqlcipher3_io_methods] object.
*/
#define SQLCIPHER_LOCK_NONE          0
#define SQLCIPHER_LOCK_SHARED        1
#define SQLCIPHER_LOCK_RESERVED      2
#define SQLCIPHER_LOCK_PENDING       3
#define SQLCIPHER_LOCK_EXCLUSIVE     4

/*
** CAPI3REF: Synchronization Type Flags
**
** When SQLite invokes the xSync() method of an
** [sqlcipher3_io_methods] object it uses a combination of
** these integer values as the second argument.
**
** When the SQLCIPHER_SYNC_DATAONLY flag is used, it means that the
** sync operation only needs to flush data to mass storage.  Inode
** information need not be flushed. If the lower four bits of the flag
** equal SQLCIPHER_SYNC_NORMAL, that means to use normal fsync() semantics.
** If the lower four bits equal SQLCIPHER_SYNC_FULL, that means
** to use Mac OS X style fullsync instead of fsync().
**
** Do not confuse the SQLCIPHER_SYNC_NORMAL and SQLCIPHER_SYNC_FULL flags
** with the [PRAGMA synchronous]=NORMAL and [PRAGMA synchronous]=FULL
** settings.  The [synchronous pragma] determines when calls to the
** xSync VFS method occur and applies uniformly across all platforms.
** The SQLCIPHER_SYNC_NORMAL and SQLCIPHER_SYNC_FULL flags determine how
** energetic or rigorous or forceful the sync operations are and
** only make a difference on Mac OSX for the default SQLite code.
** (Third-party VFS implementations might also make the distinction
** between SQLCIPHER_SYNC_NORMAL and SQLCIPHER_SYNC_FULL, but among the
** operating systems natively supported by SQLite, only Mac OSX
** cares about the difference.)
*/
#define SQLCIPHER_SYNC_NORMAL        0x00002
#define SQLCIPHER_SYNC_FULL          0x00003
#define SQLCIPHER_SYNC_DATAONLY      0x00010

/*
** CAPI3REF: OS Interface Open File Handle
**
** An [sqlcipher3_file] object represents an open file in the 
** [sqlcipher3_vfs | OS interface layer].  Individual OS interface
** implementations will
** want to subclass this object by appending additional fields
** for their own use.  The pMethods entry is a pointer to an
** [sqlcipher3_io_methods] object that defines methods for performing
** I/O operations on the open file.
*/
typedef struct sqlcipher3_file sqlcipher3_file;
struct sqlcipher3_file {
  const struct sqlcipher3_io_methods *pMethods;  /* Methods for an open file */
};

/*
** CAPI3REF: OS Interface File Virtual Methods Object
**
** Every file opened by the [sqlcipher3_vfs.xOpen] method populates an
** [sqlcipher3_file] object (or, more commonly, a subclass of the
** [sqlcipher3_file] object) with a pointer to an instance of this object.
** This object defines the methods used to perform various operations
** against the open file represented by the [sqlcipher3_file] object.
**
** If the [sqlcipher3_vfs.xOpen] method sets the sqlcipher3_file.pMethods element 
** to a non-NULL pointer, then the sqlcipher3_io_methods.xClose method
** may be invoked even if the [sqlcipher3_vfs.xOpen] reported that it failed.  The
** only way to prevent a call to xClose following a failed [sqlcipher3_vfs.xOpen]
** is for the [sqlcipher3_vfs.xOpen] to set the sqlcipher3_file.pMethods element
** to NULL.
**
** The flags argument to xSync may be one of [SQLCIPHER_SYNC_NORMAL] or
** [SQLCIPHER_SYNC_FULL].  The first choice is the normal fsync().
** The second choice is a Mac OS X style fullsync.  The [SQLCIPHER_SYNC_DATAONLY]
** flag may be ORed in to indicate that only the data of the file
** and not its inode needs to be synced.
**
** The integer values to xLock() and xUnlock() are one of
** <ul>
** <li> [SQLCIPHER_LOCK_NONE],
** <li> [SQLCIPHER_LOCK_SHARED],
** <li> [SQLCIPHER_LOCK_RESERVED],
** <li> [SQLCIPHER_LOCK_PENDING], or
** <li> [SQLCIPHER_LOCK_EXCLUSIVE].
** </ul>
** xLock() increases the lock. xUnlock() decreases the lock.
** The xCheckReservedLock() method checks whether any database connection,
** either in this process or in some other process, is holding a RESERVED,
** PENDING, or EXCLUSIVE lock on the file.  It returns true
** if such a lock exists and false otherwise.
**
** The xFileControl() method is a generic interface that allows custom
** VFS implementations to directly control an open file using the
** [sqlcipher3_file_control()] interface.  The second "op" argument is an
** integer opcode.  The third argument is a generic pointer intended to
** point to a structure that may contain arguments or space in which to
** write return values.  Potential uses for xFileControl() might be
** functions to enable blocking locks with timeouts, to change the
** locking strategy (for example to use dot-file locks), to inquire
** about the status of a lock, or to break stale locks.  The SQLite
** core reserves all opcodes less than 100 for its own use.
** A [SQLCIPHER_FCNTL_LOCKSTATE | list of opcodes] less than 100 is available.
** Applications that define a custom xFileControl method should use opcodes
** greater than 100 to avoid conflicts.  VFS implementations should
** return [SQLCIPHER_NOTFOUND] for file control opcodes that they do not
** recognize.
**
** The xSectorSize() method returns the sector size of the
** device that underlies the file.  The sector size is the
** minimum write that can be performed without disturbing
** other bytes in the file.  The xDeviceCharacteristics()
** method returns a bit vector describing behaviors of the
** underlying device:
**
** <ul>
** <li> [SQLCIPHER_IOCAP_ATOMIC]
** <li> [SQLCIPHER_IOCAP_ATOMIC512]
** <li> [SQLCIPHER_IOCAP_ATOMIC1K]
** <li> [SQLCIPHER_IOCAP_ATOMIC2K]
** <li> [SQLCIPHER_IOCAP_ATOMIC4K]
** <li> [SQLCIPHER_IOCAP_ATOMIC8K]
** <li> [SQLCIPHER_IOCAP_ATOMIC16K]
** <li> [SQLCIPHER_IOCAP_ATOMIC32K]
** <li> [SQLCIPHER_IOCAP_ATOMIC64K]
** <li> [SQLCIPHER_IOCAP_SAFE_APPEND]
** <li> [SQLCIPHER_IOCAP_SEQUENTIAL]
** </ul>
**
** The SQLCIPHER_IOCAP_ATOMIC property means that all writes of
** any size are atomic.  The SQLCIPHER_IOCAP_ATOMICnnn values
** mean that writes of blocks that are nnn bytes in size and
** are aligned to an address which is an integer multiple of
** nnn are atomic.  The SQLCIPHER_IOCAP_SAFE_APPEND value means
** that when data is appended to a file, the data is appended
** first then the size of the file is extended, never the other
** way around.  The SQLCIPHER_IOCAP_SEQUENTIAL property means that
** information is written to disk in the same order as calls
** to xWrite().
**
** If xRead() returns SQLCIPHER_IOERR_SHORT_READ it must also fill
** in the unread portions of the buffer with zeros.  A VFS that
** fails to zero-fill short reads might seem to work.  However,
** failure to zero-fill short reads will eventually lead to
** database corruption.
*/
typedef struct sqlcipher3_io_methods sqlcipher3_io_methods;
struct sqlcipher3_io_methods {
  int iVersion;
  int (*xClose)(sqlcipher3_file*);
  int (*xRead)(sqlcipher3_file*, void*, int iAmt, sqlcipher3_int64 iOfst);
  int (*xWrite)(sqlcipher3_file*, const void*, int iAmt, sqlcipher3_int64 iOfst);
  int (*xTruncate)(sqlcipher3_file*, sqlcipher3_int64 size);
  int (*xSync)(sqlcipher3_file*, int flags);
  int (*xFileSize)(sqlcipher3_file*, sqlcipher3_int64 *pSize);
  int (*xLock)(sqlcipher3_file*, int);
  int (*xUnlock)(sqlcipher3_file*, int);
  int (*xCheckReservedLock)(sqlcipher3_file*, int *pResOut);
  int (*xFileControl)(sqlcipher3_file*, int op, void *pArg);
  int (*xSectorSize)(sqlcipher3_file*);
  int (*xDeviceCharacteristics)(sqlcipher3_file*);
  /* Methods above are valid for version 1 */
  int (*xShmMap)(sqlcipher3_file*, int iPg, int pgsz, int, void volatile**);
  int (*xShmLock)(sqlcipher3_file*, int offset, int n, int flags);
  void (*xShmBarrier)(sqlcipher3_file*);
  int (*xShmUnmap)(sqlcipher3_file*, int deleteFlag);
  /* Methods above are valid for version 2 */
  /* Additional methods may be added in future releases */
};

/*
** CAPI3REF: Standard File Control Opcodes
**
** These integer constants are opcodes for the xFileControl method
** of the [sqlcipher3_io_methods] object and for the [sqlcipher3_file_control()]
** interface.
**
** The [SQLCIPHER_FCNTL_LOCKSTATE] opcode is used for debugging.  This
** opcode causes the xFileControl method to write the current state of
** the lock (one of [SQLCIPHER_LOCK_NONE], [SQLCIPHER_LOCK_SHARED],
** [SQLCIPHER_LOCK_RESERVED], [SQLCIPHER_LOCK_PENDING], or [SQLCIPHER_LOCK_EXCLUSIVE])
** into an integer that the pArg argument points to. This capability
** is used during testing and only needs to be supported when SQLCIPHER_TEST
** is defined.
**
** The [SQLCIPHER_FCNTL_SIZE_HINT] opcode is used by SQLite to give the VFS
** layer a hint of how large the database file will grow to be during the
** current transaction.  This hint is not guaranteed to be accurate but it
** is often close.  The underlying VFS might choose to preallocate database
** file space based on this hint in order to help writes to the database
** file run faster.
**
** The [SQLCIPHER_FCNTL_CHUNK_SIZE] opcode is used to request that the VFS
** extends and truncates the database file in chunks of a size specified
** by the user. The fourth argument to [sqlcipher3_file_control()] should 
** point to an integer (type int) containing the new chunk-size to use
** for the nominated database. Allocating database file space in large
** chunks (say 1MB at a time), may reduce file-system fragmentation and
** improve performance on some systems.
**
** The [SQLCIPHER_FCNTL_FILE_POINTER] opcode is used to obtain a pointer
** to the [sqlcipher3_file] object associated with a particular database
** connection.  See the [sqlcipher3_file_control()] documentation for
** additional information.
**
** ^(The [SQLCIPHER_FCNTL_SYNC_OMITTED] opcode is generated internally by
** SQLite and sent to all VFSes in place of a call to the xSync method
** when the database connection has [PRAGMA synchronous] set to OFF.)^
** Some specialized VFSes need this signal in order to operate correctly
** when [PRAGMA synchronous | PRAGMA synchronous=OFF] is set, but most 
** VFSes do not need this signal and should silently ignore this opcode.
** Applications should not call [sqlcipher3_file_control()] with this
** opcode as doing so may disrupt the operation of the specialized VFSes
** that do require it.  
**
** ^The [SQLCIPHER_FCNTL_WIN32_AV_RETRY] opcode is used to configure automatic
** retry counts and intervals for certain disk I/O operations for the
** windows [VFS] in order to work to provide robustness against
** anti-virus programs.  By default, the windows VFS will retry file read,
** file write, and file delete operations up to 10 times, with a delay
** of 25 milliseconds before the first retry and with the delay increasing
** by an additional 25 milliseconds with each subsequent retry.  This
** opcode allows those to values (10 retries and 25 milliseconds of delay)
** to be adjusted.  The values are changed for all database connections
** within the same process.  The argument is a pointer to an array of two
** integers where the first integer i the new retry count and the second
** integer is the delay.  If either integer is negative, then the setting
** is not changed but instead the prior value of that setting is written
** into the array entry, allowing the current retry settings to be
** interrogated.  The zDbName parameter is ignored.
**
** ^The [SQLCIPHER_FCNTL_PERSIST_WAL] opcode is used to set or query the
** persistent [WAL | Write AHead Log] setting.  By default, the auxiliary
** write ahead log and shared memory files used for transaction control
** are automatically deleted when the latest connection to the database
** closes.  Setting persistent WAL mode causes those files to persist after
** close.  Persisting the files is useful when other processes that do not
** have write permission on the directory containing the database file want
** to read the database file, as the WAL and shared memory files must exist
** in order for the database to be readable.  The fourth parameter to
** [sqlcipher3_file_control()] for this opcode should be a pointer to an integer.
** That integer is 0 to disable persistent WAL mode or 1 to enable persistent
** WAL mode.  If the integer is -1, then it is overwritten with the current
** WAL persistence setting.
**
** ^The [SQLCIPHER_FCNTL_OVERWRITE] opcode is invoked by SQLite after opening
** a write transaction to indicate that, unless it is rolled back for some
** reason, the entire database file will be overwritten by the current 
** transaction. This is used by VACUUM operations.
*/
#define SQLCIPHER_FCNTL_LOCKSTATE        1
#define SQLCIPHER_GET_LOCKPROXYFILE      2
#define SQLCIPHER_SET_LOCKPROXYFILE      3
#define SQLCIPHER_LAST_ERRNO             4
#define SQLCIPHER_FCNTL_SIZE_HINT        5
#define SQLCIPHER_FCNTL_CHUNK_SIZE       6
#define SQLCIPHER_FCNTL_FILE_POINTER     7
#define SQLCIPHER_FCNTL_SYNC_OMITTED     8
#define SQLCIPHER_FCNTL_WIN32_AV_RETRY   9
#define SQLCIPHER_FCNTL_PERSIST_WAL     10
#define SQLCIPHER_FCNTL_OVERWRITE       11

/*
** CAPI3REF: Mutex Handle
**
** The mutex module within SQLite defines [sqlcipher3_mutex] to be an
** abstract type for a mutex object.  The SQLite core never looks
** at the internal representation of an [sqlcipher3_mutex].  It only
** deals with pointers to the [sqlcipher3_mutex] object.
**
** Mutexes are created using [sqlcipher3_mutex_alloc()].
*/
typedef struct sqlcipher3_mutex sqlcipher3_mutex;

/*
** CAPI3REF: OS Interface Object
**
** An instance of the sqlcipher3_vfs object defines the interface between
** the SQLite core and the underlying operating system.  The "vfs"
** in the name of the object stands for "virtual file system".  See
** the [VFS | VFS documentation] for further information.
**
** The value of the iVersion field is initially 1 but may be larger in
** future versions of SQLite.  Additional fields may be appended to this
** object when the iVersion value is increased.  Note that the structure
** of the sqlcipher3_vfs object changes in the transaction between
** SQLite version 3.5.9 and 3.6.0 and yet the iVersion field was not
** modified.
**
** The szOsFile field is the size of the subclassed [sqlcipher3_file]
** structure used by this VFS.  mxPathname is the maximum length of
** a pathname in this VFS.
**
** Registered sqlcipher3_vfs objects are kept on a linked list formed by
** the pNext pointer.  The [sqlcipher3_vfs_register()]
** and [sqlcipher3_vfs_unregister()] interfaces manage this list
** in a thread-safe way.  The [sqlcipher3_vfs_find()] interface
** searches the list.  Neither the application code nor the VFS
** implementation should use the pNext pointer.
**
** The pNext field is the only field in the sqlcipher3_vfs
** structure that SQLite will ever modify.  SQLite will only access
** or modify this field while holding a particular static mutex.
** The application should never modify anything within the sqlcipher3_vfs
** object once the object has been registered.
**
** The zName field holds the name of the VFS module.  The name must
** be unique across all VFS modules.
**
** [[sqlcipher3_vfs.xOpen]]
** ^SQLite guarantees that the zFilename parameter to xOpen
** is either a NULL pointer or string obtained
** from xFullPathname() with an optional suffix added.
** ^If a suffix is added to the zFilename parameter, it will
** consist of a single "-" character followed by no more than
** 10 alphanumeric and/or "-" characters.
** ^SQLite further guarantees that
** the string will be valid and unchanged until xClose() is
** called. Because of the previous sentence,
** the [sqlcipher3_file] can safely store a pointer to the
** filename if it needs to remember the filename for some reason.
** If the zFilename parameter to xOpen is a NULL pointer then xOpen
** must invent its own temporary name for the file.  ^Whenever the 
** xFilename parameter is NULL it will also be the case that the
** flags parameter will include [SQLCIPHER_OPEN_DELETEONCLOSE].
**
** The flags argument to xOpen() includes all bits set in
** the flags argument to [sqlcipher3_open_v2()].  Or if [sqlcipher3_open()]
** or [sqlcipher3_open16()] is used, then flags includes at least
** [SQLCIPHER_OPEN_READWRITE] | [SQLCIPHER_OPEN_CREATE]. 
** If xOpen() opens a file read-only then it sets *pOutFlags to
** include [SQLCIPHER_OPEN_READONLY].  Other bits in *pOutFlags may be set.
**
** ^(SQLite will also add one of the following flags to the xOpen()
** call, depending on the object being opened:
**
** <ul>
** <li>  [SQLCIPHER_OPEN_MAIN_DB]
** <li>  [SQLCIPHER_OPEN_MAIN_JOURNAL]
** <li>  [SQLCIPHER_OPEN_TEMP_DB]
** <li>  [SQLCIPHER_OPEN_TEMP_JOURNAL]
** <li>  [SQLCIPHER_OPEN_TRANSIENT_DB]
** <li>  [SQLCIPHER_OPEN_SUBJOURNAL]
** <li>  [SQLCIPHER_OPEN_MASTER_JOURNAL]
** <li>  [SQLCIPHER_OPEN_WAL]
** </ul>)^
**
** The file I/O implementation can use the object type flags to
** change the way it deals with files.  For example, an application
** that does not care about crash recovery or rollback might make
** the open of a journal file a no-op.  Writes to this journal would
** also be no-ops, and any attempt to read the journal would return
** SQLCIPHER_IOERR.  Or the implementation might recognize that a database
** file will be doing page-aligned sector reads and writes in a random
** order and set up its I/O subsystem accordingly.
**
** SQLite might also add one of the following flags to the xOpen method:
**
** <ul>
** <li> [SQLCIPHER_OPEN_DELETEONCLOSE]
** <li> [SQLCIPHER_OPEN_EXCLUSIVE]
** </ul>
**
** The [SQLCIPHER_OPEN_DELETEONCLOSE] flag means the file should be
** deleted when it is closed.  ^The [SQLCIPHER_OPEN_DELETEONCLOSE]
** will be set for TEMP databases and their journals, transient
** databases, and subjournals.
**
** ^The [SQLCIPHER_OPEN_EXCLUSIVE] flag is always used in conjunction
** with the [SQLCIPHER_OPEN_CREATE] flag, which are both directly
** analogous to the O_EXCL and O_CREAT flags of the POSIX open()
** API.  The SQLCIPHER_OPEN_EXCLUSIVE flag, when paired with the 
** SQLCIPHER_OPEN_CREATE, is used to indicate that file should always
** be created, and that it is an error if it already exists.
** It is <i>not</i> used to indicate the file should be opened 
** for exclusive access.
**
** ^At least szOsFile bytes of memory are allocated by SQLite
** to hold the  [sqlcipher3_file] structure passed as the third
** argument to xOpen.  The xOpen method does not have to
** allocate the structure; it should just fill it in.  Note that
** the xOpen method must set the sqlcipher3_file.pMethods to either
** a valid [sqlcipher3_io_methods] object or to NULL.  xOpen must do
** this even if the open fails.  SQLite expects that the sqlcipher3_file.pMethods
** element will be valid after xOpen returns regardless of the success
** or failure of the xOpen call.
**
** [[sqlcipher3_vfs.xAccess]]
** ^The flags argument to xAccess() may be [SQLCIPHER_ACCESS_EXISTS]
** to test for the existence of a file, or [SQLCIPHER_ACCESS_READWRITE] to
** test whether a file is readable and writable, or [SQLCIPHER_ACCESS_READ]
** to test whether a file is at least readable.   The file can be a
** directory.
**
** ^SQLite will always allocate at least mxPathname+1 bytes for the
** output buffer xFullPathname.  The exact size of the output buffer
** is also passed as a parameter to both  methods. If the output buffer
** is not large enough, [SQLCIPHER_CANTOPEN] should be returned. Since this is
** handled as a fatal error by SQLite, vfs implementations should endeavor
** to prevent this by setting mxPathname to a sufficiently large value.
**
** The xRandomness(), xSleep(), xCurrentTime(), and xCurrentTimeInt64()
** interfaces are not strictly a part of the filesystem, but they are
** included in the VFS structure for completeness.
** The xRandomness() function attempts to return nBytes bytes
** of good-quality randomness into zOut.  The return value is
** the actual number of bytes of randomness obtained.
** The xSleep() method causes the calling thread to sleep for at
** least the number of microseconds given.  ^The xCurrentTime()
** method returns a Julian Day Number for the current date and time as
** a floating point value.
** ^The xCurrentTimeInt64() method returns, as an integer, the Julian
** Day Number multiplied by 86400000 (the number of milliseconds in 
** a 24-hour day).  
** ^SQLite will use the xCurrentTimeInt64() method to get the current
** date and time if that method is available (if iVersion is 2 or 
** greater and the function pointer is not NULL) and will fall back
** to xCurrentTime() if xCurrentTimeInt64() is unavailable.
**
** ^The xSetSystemCall(), xGetSystemCall(), and xNestSystemCall() interfaces
** are not used by the SQLite core.  These optional interfaces are provided
** by some VFSes to facilitate testing of the VFS code. By overriding 
** system calls with functions under its control, a test program can
** simulate faults and error conditions that would otherwise be difficult
** or impossible to induce.  The set of system calls that can be overridden
** varies from one VFS to another, and from one version of the same VFS to the
** next.  Applications that use these interfaces must be prepared for any
** or all of these interfaces to be NULL or for their behavior to change
** from one release to the next.  Applications must not attempt to access
** any of these methods if the iVersion of the VFS is less than 3.
*/
typedef struct sqlcipher3_vfs sqlcipher3_vfs;
typedef void (*sqlcipher3_syscall_ptr)(void);
struct sqlcipher3_vfs {
  int iVersion;            /* Structure version number (currently 3) */
  int szOsFile;            /* Size of subclassed sqlcipher3_file */
  int mxPathname;          /* Maximum file pathname length */
  sqlcipher3_vfs *pNext;      /* Next registered VFS */
  const char *zName;       /* Name of this virtual file system */
  void *pAppData;          /* Pointer to application-specific data */
  int (*xOpen)(sqlcipher3_vfs*, const char *zName, sqlcipher3_file*,
               int flags, int *pOutFlags);
  int (*xDelete)(sqlcipher3_vfs*, const char *zName, int syncDir);
  int (*xAccess)(sqlcipher3_vfs*, const char *zName, int flags, int *pResOut);
  int (*xFullPathname)(sqlcipher3_vfs*, const char *zName, int nOut, char *zOut);
  void *(*xDlOpen)(sqlcipher3_vfs*, const char *zFilename);
  void (*xDlError)(sqlcipher3_vfs*, int nByte, char *zErrMsg);
  void (*(*xDlSym)(sqlcipher3_vfs*,void*, const char *zSymbol))(void);
  void (*xDlClose)(sqlcipher3_vfs*, void*);
  int (*xRandomness)(sqlcipher3_vfs*, int nByte, char *zOut);
  int (*xSleep)(sqlcipher3_vfs*, int microseconds);
  int (*xCurrentTime)(sqlcipher3_vfs*, double*);
  int (*xGetLastError)(sqlcipher3_vfs*, int, char *);
  /*
  ** The methods above are in version 1 of the sqlcipher_vfs object
  ** definition.  Those that follow are added in version 2 or later
  */
  int (*xCurrentTimeInt64)(sqlcipher3_vfs*, sqlcipher3_int64*);
  /*
  ** The methods above are in versions 1 and 2 of the sqlcipher_vfs object.
  ** Those below are for version 3 and greater.
  */
  int (*xSetSystemCall)(sqlcipher3_vfs*, const char *zName, sqlcipher3_syscall_ptr);
  sqlcipher3_syscall_ptr (*xGetSystemCall)(sqlcipher3_vfs*, const char *zName);
  const char *(*xNextSystemCall)(sqlcipher3_vfs*, const char *zName);
  /*
  ** The methods above are in versions 1 through 3 of the sqlcipher_vfs object.
  ** New fields may be appended in figure versions.  The iVersion
  ** value will increment whenever this happens. 
  */
};

/*
** CAPI3REF: Flags for the xAccess VFS method
**
** These integer constants can be used as the third parameter to
** the xAccess method of an [sqlcipher3_vfs] object.  They determine
** what kind of permissions the xAccess method is looking for.
** With SQLCIPHER_ACCESS_EXISTS, the xAccess method
** simply checks whether the file exists.
** With SQLCIPHER_ACCESS_READWRITE, the xAccess method
** checks whether the named directory is both readable and writable
** (in other words, if files can be added, removed, and renamed within
** the directory).
** The SQLCIPHER_ACCESS_READWRITE constant is currently used only by the
** [temp_store_directory pragma], though this could change in a future
** release of SQLite.
** With SQLCIPHER_ACCESS_READ, the xAccess method
** checks whether the file is readable.  The SQLCIPHER_ACCESS_READ constant is
** currently unused, though it might be used in a future release of
** SQLite.
*/
#define SQLCIPHER_ACCESS_EXISTS    0
#define SQLCIPHER_ACCESS_READWRITE 1   /* Used by PRAGMA temp_store_directory */
#define SQLCIPHER_ACCESS_READ      2   /* Unused */

/*
** CAPI3REF: Flags for the xShmLock VFS method
**
** These integer constants define the various locking operations
** allowed by the xShmLock method of [sqlcipher3_io_methods].  The
** following are the only legal combinations of flags to the
** xShmLock method:
**
** <ul>
** <li>  SQLCIPHER_SHM_LOCK | SQLCIPHER_SHM_SHARED
** <li>  SQLCIPHER_SHM_LOCK | SQLCIPHER_SHM_EXCLUSIVE
** <li>  SQLCIPHER_SHM_UNLOCK | SQLCIPHER_SHM_SHARED
** <li>  SQLCIPHER_SHM_UNLOCK | SQLCIPHER_SHM_EXCLUSIVE
** </ul>
**
** When unlocking, the same SHARED or EXCLUSIVE flag must be supplied as
** was given no the corresponding lock.  
**
** The xShmLock method can transition between unlocked and SHARED or
** between unlocked and EXCLUSIVE.  It cannot transition between SHARED
** and EXCLUSIVE.
*/
#define SQLCIPHER_SHM_UNLOCK       1
#define SQLCIPHER_SHM_LOCK         2
#define SQLCIPHER_SHM_SHARED       4
#define SQLCIPHER_SHM_EXCLUSIVE    8

/*
** CAPI3REF: Maximum xShmLock index
**
** The xShmLock method on [sqlcipher3_io_methods] may use values
** between 0 and this upper bound as its "offset" argument.
** The SQLite core will never attempt to acquire or release a
** lock outside of this range
*/
#define SQLCIPHER_SHM_NLOCK        8


/*
** CAPI3REF: Initialize The SQLite Library
**
** ^The sqlcipher3_initialize() routine initializes the
** SQLite library.  ^The sqlcipher3_shutdown() routine
** deallocates any resources that were allocated by sqlcipher3_initialize().
** These routines are designed to aid in process initialization and
** shutdown on embedded systems.  Workstation applications using
** SQLite normally do not need to invoke either of these routines.
**
** A call to sqlcipher3_initialize() is an "effective" call if it is
** the first time sqlcipher3_initialize() is invoked during the lifetime of
** the process, or if it is the first time sqlcipher3_initialize() is invoked
** following a call to sqlcipher3_shutdown().  ^(Only an effective call
** of sqlcipher3_initialize() does any initialization.  All other calls
** are harmless no-ops.)^
**
** A call to sqlcipher3_shutdown() is an "effective" call if it is the first
** call to sqlcipher3_shutdown() since the last sqlcipher3_initialize().  ^(Only
** an effective call to sqlcipher3_shutdown() does any deinitialization.
** All other valid calls to sqlcipher3_shutdown() are harmless no-ops.)^
**
** The sqlcipher3_initialize() interface is threadsafe, but sqlcipher3_shutdown()
** is not.  The sqlcipher3_shutdown() interface must only be called from a
** single thread.  All open [database connections] must be closed and all
** other SQLite resources must be deallocated prior to invoking
** sqlcipher3_shutdown().
**
** Among other things, ^sqlcipher3_initialize() will invoke
** sqlcipher3_os_init().  Similarly, ^sqlcipher3_shutdown()
** will invoke sqlcipher3_os_end().
**
** ^The sqlcipher3_initialize() routine returns [SQLCIPHER_OK] on success.
** ^If for some reason, sqlcipher3_initialize() is unable to initialize
** the library (perhaps it is unable to allocate a needed resource such
** as a mutex) it returns an [error code] other than [SQLCIPHER_OK].
**
** ^The sqlcipher3_initialize() routine is called internally by many other
** SQLite interfaces so that an application usually does not need to
** invoke sqlcipher3_initialize() directly.  For example, [sqlcipher3_open()]
** calls sqlcipher3_initialize() so the SQLite library will be automatically
** initialized when [sqlcipher3_open()] is called if it has not be initialized
** already.  ^However, if SQLite is compiled with the [SQLCIPHER_OMIT_AUTOINIT]
** compile-time option, then the automatic calls to sqlcipher3_initialize()
** are omitted and the application must call sqlcipher3_initialize() directly
** prior to using any other SQLite interface.  For maximum portability,
** it is recommended that applications always invoke sqlcipher3_initialize()
** directly prior to using any other SQLite interface.  Future releases
** of SQLite may require this.  In other words, the behavior exhibited
** when SQLite is compiled with [SQLCIPHER_OMIT_AUTOINIT] might become the
** default behavior in some future release of SQLite.
**
** The sqlcipher3_os_init() routine does operating-system specific
** initialization of the SQLite library.  The sqlcipher3_os_end()
** routine undoes the effect of sqlcipher3_os_init().  Typical tasks
** performed by these routines include allocation or deallocation
** of static resources, initialization of global variables,
** setting up a default [sqlcipher3_vfs] module, or setting up
** a default configuration using [sqlcipher3_config()].
**
** The application should never invoke either sqlcipher3_os_init()
** or sqlcipher3_os_end() directly.  The application should only invoke
** sqlcipher3_initialize() and sqlcipher3_shutdown().  The sqlcipher3_os_init()
** interface is called automatically by sqlcipher3_initialize() and
** sqlcipher3_os_end() is called by sqlcipher3_shutdown().  Appropriate
** implementations for sqlcipher3_os_init() and sqlcipher3_os_end()
** are built into SQLite when it is compiled for Unix, Windows, or OS/2.
** When [custom builds | built for other platforms]
** (using the [SQLCIPHER_OS_OTHER=1] compile-time
** option) the application must supply a suitable implementation for
** sqlcipher3_os_init() and sqlcipher3_os_end().  An application-supplied
** implementation of sqlcipher3_os_init() or sqlcipher3_os_end()
** must return [SQLCIPHER_OK] on success and some other [error code] upon
** failure.
*/
SQLCIPHER_API int sqlcipher3_initialize(void);
SQLCIPHER_API int sqlcipher3_shutdown(void);
SQLCIPHER_API int sqlcipher3_os_init(void);
SQLCIPHER_API int sqlcipher3_os_end(void);

/*
** CAPI3REF: Configuring The SQLite Library
**
** The sqlcipher3_config() interface is used to make global configuration
** changes to SQLite in order to tune SQLite to the specific needs of
** the application.  The default configuration is recommended for most
** applications and so this routine is usually not necessary.  It is
** provided to support rare applications with unusual needs.
**
** The sqlcipher3_config() interface is not threadsafe.  The application
** must insure that no other SQLite interfaces are invoked by other
** threads while sqlcipher3_config() is running.  Furthermore, sqlcipher3_config()
** may only be invoked prior to library initialization using
** [sqlcipher3_initialize()] or after shutdown by [sqlcipher3_shutdown()].
** ^If sqlcipher3_config() is called after [sqlcipher3_initialize()] and before
** [sqlcipher3_shutdown()] then it will return SQLCIPHER_MISUSE.
** Note, however, that ^sqlcipher3_config() can be called as part of the
** implementation of an application-defined [sqlcipher3_os_init()].
**
** The first argument to sqlcipher3_config() is an integer
** [configuration option] that determines
** what property of SQLite is to be configured.  Subsequent arguments
** vary depending on the [configuration option]
** in the first argument.
**
** ^When a configuration option is set, sqlcipher3_config() returns [SQLCIPHER_OK].
** ^If the option is unknown or SQLite is unable to set the option
** then this routine returns a non-zero [error code].
*/
SQLCIPHER_API int sqlcipher3_config(int, ...);

/*
** CAPI3REF: Configure database connections
**
** The sqlcipher3_db_config() interface is used to make configuration
** changes to a [database connection].  The interface is similar to
** [sqlcipher3_config()] except that the changes apply to a single
** [database connection] (specified in the first argument).
**
** The second argument to sqlcipher3_db_config(D,V,...)  is the
** [SQLCIPHER_DBCONFIG_LOOKASIDE | configuration verb] - an integer code 
** that indicates what aspect of the [database connection] is being configured.
** Subsequent arguments vary depending on the configuration verb.
**
** ^Calls to sqlcipher3_db_config() return SQLCIPHER_OK if and only if
** the call is considered successful.
*/
SQLCIPHER_API int sqlcipher3_db_config(sqlcipher3*, int op, ...);

/*
** CAPI3REF: Memory Allocation Routines
**
** An instance of this object defines the interface between SQLite
** and low-level memory allocation routines.
**
** This object is used in only one place in the SQLite interface.
** A pointer to an instance of this object is the argument to
** [sqlcipher3_config()] when the configuration option is
** [SQLCIPHER_CONFIG_MALLOC] or [SQLCIPHER_CONFIG_GETMALLOC].  
** By creating an instance of this object
** and passing it to [sqlcipher3_config]([SQLCIPHER_CONFIG_MALLOC])
** during configuration, an application can specify an alternative
** memory allocation subsystem for SQLite to use for all of its
** dynamic memory needs.
**
** Note that SQLite comes with several [built-in memory allocators]
** that are perfectly adequate for the overwhelming majority of applications
** and that this object is only useful to a tiny minority of applications
** with specialized memory allocation requirements.  This object is
** also used during testing of SQLite in order to specify an alternative
** memory allocator that simulates memory out-of-memory conditions in
** order to verify that SQLite recovers gracefully from such
** conditions.
**
** The xMalloc, xRealloc, and xFree methods must work like the
** malloc(), realloc() and free() functions from the standard C library.
** ^SQLite guarantees that the second argument to
** xRealloc is always a value returned by a prior call to xRoundup.
**
** xSize should return the allocated size of a memory allocation
** previously obtained from xMalloc or xRealloc.  The allocated size
** is always at least as big as the requested size but may be larger.
**
** The xRoundup method returns what would be the allocated size of
** a memory allocation given a particular requested size.  Most memory
** allocators round up memory allocations at least to the next multiple
** of 8.  Some allocators round up to a larger multiple or to a power of 2.
** Every memory allocation request coming in through [sqlcipher3_malloc()]
** or [sqlcipher3_realloc()] first calls xRoundup.  If xRoundup returns 0, 
** that causes the corresponding memory allocation to fail.
**
** The xInit method initializes the memory allocator.  (For example,
** it might allocate any require mutexes or initialize internal data
** structures.  The xShutdown method is invoked (indirectly) by
** [sqlcipher3_shutdown()] and should deallocate any resources acquired
** by xInit.  The pAppData pointer is used as the only parameter to
** xInit and xShutdown.
**
** SQLite holds the [SQLCIPHER_MUTEX_STATIC_MASTER] mutex when it invokes
** the xInit method, so the xInit method need not be threadsafe.  The
** xShutdown method is only called from [sqlcipher3_shutdown()] so it does
** not need to be threadsafe either.  For all other methods, SQLite
** holds the [SQLCIPHER_MUTEX_STATIC_MEM] mutex as long as the
** [SQLCIPHER_CONFIG_MEMSTATUS] configuration option is turned on (which
** it is by default) and so the methods are automatically serialized.
** However, if [SQLCIPHER_CONFIG_MEMSTATUS] is disabled, then the other
** methods must be threadsafe or else make their own arrangements for
** serialization.
**
** SQLite will never invoke xInit() more than once without an intervening
** call to xShutdown().
*/
typedef struct sqlcipher3_mem_methods sqlcipher3_mem_methods;
struct sqlcipher3_mem_methods {
  void *(*xMalloc)(int);         /* Memory allocation function */
  void (*xFree)(void*);          /* Free a prior allocation */
  void *(*xRealloc)(void*,int);  /* Resize an allocation */
  int (*xSize)(void*);           /* Return the size of an allocation */
  int (*xRoundup)(int);          /* Round up request size to allocation size */
  int (*xInit)(void*);           /* Initialize the memory allocator */
  void (*xShutdown)(void*);      /* Deinitialize the memory allocator */
  void *pAppData;                /* Argument to xInit() and xShutdown() */
};

/*
** CAPI3REF: Configuration Options
** KEYWORDS: {configuration option}
**
** These constants are the available integer configuration options that
** can be passed as the first argument to the [sqlcipher3_config()] interface.
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlcipher3_config()] to make sure that
** the call worked.  The [sqlcipher3_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** [[SQLCIPHER_CONFIG_SINGLETHREAD]] <dt>SQLCIPHER_CONFIG_SINGLETHREAD</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Single-thread.  In other words, it disables
** all mutexing and puts SQLite into a mode where it can only be used
** by a single thread.   ^If SQLite is compiled with
** the [SQLCIPHER_THREADSAFE | SQLCIPHER_THREADSAFE=0] compile-time option then
** it is not possible to change the [threading mode] from its default
** value of Single-thread and so [sqlcipher3_config()] will return 
** [SQLCIPHER_ERROR] if called with the SQLCIPHER_CONFIG_SINGLETHREAD
** configuration option.</dd>
**
** [[SQLCIPHER_CONFIG_MULTITHREAD]] <dt>SQLCIPHER_CONFIG_MULTITHREAD</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Multi-thread.  In other words, it disables
** mutexing on [database connection] and [prepared statement] objects.
** The application is responsible for serializing access to
** [database connections] and [prepared statements].  But other mutexes
** are enabled so that SQLite will be safe to use in a multi-threaded
** environment as long as no two threads attempt to use the same
** [database connection] at the same time.  ^If SQLite is compiled with
** the [SQLCIPHER_THREADSAFE | SQLCIPHER_THREADSAFE=0] compile-time option then
** it is not possible to set the Multi-thread [threading mode] and
** [sqlcipher3_config()] will return [SQLCIPHER_ERROR] if called with the
** SQLCIPHER_CONFIG_MULTITHREAD configuration option.</dd>
**
** [[SQLCIPHER_CONFIG_SERIALIZED]] <dt>SQLCIPHER_CONFIG_SERIALIZED</dt>
** <dd>There are no arguments to this option.  ^This option sets the
** [threading mode] to Serialized. In other words, this option enables
** all mutexes including the recursive
** mutexes on [database connection] and [prepared statement] objects.
** In this mode (which is the default when SQLite is compiled with
** [SQLCIPHER_THREADSAFE=1]) the SQLite library will itself serialize access
** to [database connections] and [prepared statements] so that the
** application is free to use the same [database connection] or the
** same [prepared statement] in different threads at the same time.
** ^If SQLite is compiled with
** the [SQLCIPHER_THREADSAFE | SQLCIPHER_THREADSAFE=0] compile-time option then
** it is not possible to set the Serialized [threading mode] and
** [sqlcipher3_config()] will return [SQLCIPHER_ERROR] if called with the
** SQLCIPHER_CONFIG_SERIALIZED configuration option.</dd>
**
** [[SQLCIPHER_CONFIG_MALLOC]] <dt>SQLCIPHER_CONFIG_MALLOC</dt>
** <dd> ^(This option takes a single argument which is a pointer to an
** instance of the [sqlcipher3_mem_methods] structure.  The argument specifies
** alternative low-level memory allocation routines to be used in place of
** the memory allocation routines built into SQLite.)^ ^SQLite makes
** its own private copy of the content of the [sqlcipher3_mem_methods] structure
** before the [sqlcipher3_config()] call returns.</dd>
**
** [[SQLCIPHER_CONFIG_GETMALLOC]] <dt>SQLCIPHER_CONFIG_GETMALLOC</dt>
** <dd> ^(This option takes a single argument which is a pointer to an
** instance of the [sqlcipher3_mem_methods] structure.  The [sqlcipher3_mem_methods]
** structure is filled with the currently defined memory allocation routines.)^
** This option can be used to overload the default memory allocation
** routines with a wrapper that simulations memory allocation failure or
** tracks memory usage, for example. </dd>
**
** [[SQLCIPHER_CONFIG_MEMSTATUS]] <dt>SQLCIPHER_CONFIG_MEMSTATUS</dt>
** <dd> ^This option takes single argument of type int, interpreted as a 
** boolean, which enables or disables the collection of memory allocation 
** statistics. ^(When memory allocation statistics are disabled, the 
** following SQLite interfaces become non-operational:
**   <ul>
**   <li> [sqlcipher3_memory_used()]
**   <li> [sqlcipher3_memory_highwater()]
**   <li> [sqlcipher3_soft_heap_limit64()]
**   <li> [sqlcipher3_status()]
**   </ul>)^
** ^Memory allocation statistics are enabled by default unless SQLite is
** compiled with [SQLCIPHER_DEFAULT_MEMSTATUS]=0 in which case memory
** allocation statistics are disabled by default.
** </dd>
**
** [[SQLCIPHER_CONFIG_SCRATCH]] <dt>SQLCIPHER_CONFIG_SCRATCH</dt>
** <dd> ^This option specifies a static memory buffer that SQLite can use for
** scratch memory.  There are three arguments:  A pointer an 8-byte
** aligned memory buffer from which the scratch allocations will be
** drawn, the size of each scratch allocation (sz),
** and the maximum number of scratch allocations (N).  The sz
** argument must be a multiple of 16.
** The first argument must be a pointer to an 8-byte aligned buffer
** of at least sz*N bytes of memory.
** ^SQLite will use no more than two scratch buffers per thread.  So
** N should be set to twice the expected maximum number of threads.
** ^SQLite will never require a scratch buffer that is more than 6
** times the database page size. ^If SQLite needs needs additional
** scratch memory beyond what is provided by this configuration option, then 
** [sqlcipher3_malloc()] will be used to obtain the memory needed.</dd>
**
** [[SQLCIPHER_CONFIG_PAGECACHE]] <dt>SQLCIPHER_CONFIG_PAGECACHE</dt>
** <dd> ^This option specifies a static memory buffer that SQLite can use for
** the database page cache with the default page cache implementation.  
** This configuration should not be used if an application-define page
** cache implementation is loaded using the SQLCIPHER_CONFIG_PCACHE option.
** There are three arguments to this option: A pointer to 8-byte aligned
** memory, the size of each page buffer (sz), and the number of pages (N).
** The sz argument should be the size of the largest database page
** (a power of two between 512 and 32768) plus a little extra for each
** page header.  ^The page header size is 20 to 40 bytes depending on
** the host architecture.  ^It is harmless, apart from the wasted memory,
** to make sz a little too large.  The first
** argument should point to an allocation of at least sz*N bytes of memory.
** ^SQLite will use the memory provided by the first argument to satisfy its
** memory needs for the first N pages that it adds to cache.  ^If additional
** page cache memory is needed beyond what is provided by this option, then
** SQLite goes to [sqlcipher3_malloc()] for the additional storage space.
** The pointer in the first argument must
** be aligned to an 8-byte boundary or subsequent behavior of SQLite
** will be undefined.</dd>
**
** [[SQLCIPHER_CONFIG_HEAP]] <dt>SQLCIPHER_CONFIG_HEAP</dt>
** <dd> ^This option specifies a static memory buffer that SQLite will use
** for all of its dynamic memory allocation needs beyond those provided
** for by [SQLCIPHER_CONFIG_SCRATCH] and [SQLCIPHER_CONFIG_PAGECACHE].
** There are three arguments: An 8-byte aligned pointer to the memory,
** the number of bytes in the memory buffer, and the minimum allocation size.
** ^If the first pointer (the memory pointer) is NULL, then SQLite reverts
** to using its default memory allocator (the system malloc() implementation),
** undoing any prior invocation of [SQLCIPHER_CONFIG_MALLOC].  ^If the
** memory pointer is not NULL and either [SQLCIPHER_ENABLE_MEMSYS3] or
** [SQLCIPHER_ENABLE_MEMSYS5] are defined, then the alternative memory
** allocator is engaged to handle all of SQLites memory allocation needs.
** The first pointer (the memory pointer) must be aligned to an 8-byte
** boundary or subsequent behavior of SQLite will be undefined.
** The minimum allocation size is capped at 2**12. Reasonable values
** for the minimum allocation size are 2**5 through 2**8.</dd>
**
** [[SQLCIPHER_CONFIG_MUTEX]] <dt>SQLCIPHER_CONFIG_MUTEX</dt>
** <dd> ^(This option takes a single argument which is a pointer to an
** instance of the [sqlcipher3_mutex_methods] structure.  The argument specifies
** alternative low-level mutex routines to be used in place
** the mutex routines built into SQLite.)^  ^SQLite makes a copy of the
** content of the [sqlcipher3_mutex_methods] structure before the call to
** [sqlcipher3_config()] returns. ^If SQLite is compiled with
** the [SQLCIPHER_THREADSAFE | SQLCIPHER_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlcipher3_config()] with the SQLCIPHER_CONFIG_MUTEX configuration option will
** return [SQLCIPHER_ERROR].</dd>
**
** [[SQLCIPHER_CONFIG_GETMUTEX]] <dt>SQLCIPHER_CONFIG_GETMUTEX</dt>
** <dd> ^(This option takes a single argument which is a pointer to an
** instance of the [sqlcipher3_mutex_methods] structure.  The
** [sqlcipher3_mutex_methods]
** structure is filled with the currently defined mutex routines.)^
** This option can be used to overload the default mutex allocation
** routines with a wrapper used to track mutex usage for performance
** profiling or testing, for example.   ^If SQLite is compiled with
** the [SQLCIPHER_THREADSAFE | SQLCIPHER_THREADSAFE=0] compile-time option then
** the entire mutexing subsystem is omitted from the build and hence calls to
** [sqlcipher3_config()] with the SQLCIPHER_CONFIG_GETMUTEX configuration option will
** return [SQLCIPHER_ERROR].</dd>
**
** [[SQLCIPHER_CONFIG_LOOKASIDE]] <dt>SQLCIPHER_CONFIG_LOOKASIDE</dt>
** <dd> ^(This option takes two arguments that determine the default
** memory allocation for the lookaside memory allocator on each
** [database connection].  The first argument is the
** size of each lookaside buffer slot and the second is the number of
** slots allocated to each database connection.)^  ^(This option sets the
** <i>default</i> lookaside size. The [SQLCIPHER_DBCONFIG_LOOKASIDE]
** verb to [sqlcipher3_db_config()] can be used to change the lookaside
** configuration on individual connections.)^ </dd>
**
** [[SQLCIPHER_CONFIG_PCACHE]] <dt>SQLCIPHER_CONFIG_PCACHE</dt>
** <dd> ^(This option takes a single argument which is a pointer to
** an [sqlcipher3_pcache_methods] object.  This object specifies the interface
** to a custom page cache implementation.)^  ^SQLite makes a copy of the
** object and uses it for page cache memory allocations.</dd>
**
** [[SQLCIPHER_CONFIG_GETPCACHE]] <dt>SQLCIPHER_CONFIG_GETPCACHE</dt>
** <dd> ^(This option takes a single argument which is a pointer to an
** [sqlcipher3_pcache_methods] object.  SQLite copies of the current
** page cache implementation into that object.)^ </dd>
**
** [[SQLCIPHER_CONFIG_LOG]] <dt>SQLCIPHER_CONFIG_LOG</dt>
** <dd> ^The SQLCIPHER_CONFIG_LOG option takes two arguments: a pointer to a
** function with a call signature of void(*)(void*,int,const char*), 
** and a pointer to void. ^If the function pointer is not NULL, it is
** invoked by [sqlcipher3_log()] to process each logging event.  ^If the
** function pointer is NULL, the [sqlcipher3_log()] interface becomes a no-op.
** ^The void pointer that is the second argument to SQLCIPHER_CONFIG_LOG is
** passed through as the first parameter to the application-defined logger
** function whenever that function is invoked.  ^The second parameter to
** the logger function is a copy of the first parameter to the corresponding
** [sqlcipher3_log()] call and is intended to be a [result code] or an
** [extended result code].  ^The third parameter passed to the logger is
** log message after formatting via [sqlcipher3_snprintf()].
** The SQLite logging interface is not reentrant; the logger function
** supplied by the application must not invoke any SQLite interface.
** In a multi-threaded application, the application-defined logger
** function must be threadsafe. </dd>
**
** [[SQLCIPHER_CONFIG_URI]] <dt>SQLCIPHER_CONFIG_URI
** <dd> This option takes a single argument of type int. If non-zero, then
** URI handling is globally enabled. If the parameter is zero, then URI handling
** is globally disabled. If URI handling is globally enabled, all filenames
** passed to [sqlcipher3_open()], [sqlcipher3_open_v2()], [sqlcipher3_open16()] or
** specified as part of [ATTACH] commands are interpreted as URIs, regardless
** of whether or not the [SQLCIPHER_OPEN_URI] flag is set when the database
** connection is opened. If it is globally disabled, filenames are
** only interpreted as URIs if the SQLCIPHER_OPEN_URI flag is set when the
** database connection is opened. By default, URI handling is globally
** disabled. The default value may be changed by compiling with the
** [SQLCIPHER_USE_URI] symbol defined.
** </dl>
*/
#define SQLCIPHER_CONFIG_SINGLETHREAD  1  /* nil */
#define SQLCIPHER_CONFIG_MULTITHREAD   2  /* nil */
#define SQLCIPHER_CONFIG_SERIALIZED    3  /* nil */
#define SQLCIPHER_CONFIG_MALLOC        4  /* sqlcipher3_mem_methods* */
#define SQLCIPHER_CONFIG_GETMALLOC     5  /* sqlcipher3_mem_methods* */
#define SQLCIPHER_CONFIG_SCRATCH       6  /* void*, int sz, int N */
#define SQLCIPHER_CONFIG_PAGECACHE     7  /* void*, int sz, int N */
#define SQLCIPHER_CONFIG_HEAP          8  /* void*, int nByte, int min */
#define SQLCIPHER_CONFIG_MEMSTATUS     9  /* boolean */
#define SQLCIPHER_CONFIG_MUTEX        10  /* sqlcipher3_mutex_methods* */
#define SQLCIPHER_CONFIG_GETMUTEX     11  /* sqlcipher3_mutex_methods* */
/* previously SQLCIPHER_CONFIG_CHUNKALLOC 12 which is now unused. */ 
#define SQLCIPHER_CONFIG_LOOKASIDE    13  /* int int */
#define SQLCIPHER_CONFIG_PCACHE       14  /* sqlcipher3_pcache_methods* */
#define SQLCIPHER_CONFIG_GETPCACHE    15  /* sqlcipher3_pcache_methods* */
#define SQLCIPHER_CONFIG_LOG          16  /* xFunc, void* */
#define SQLCIPHER_CONFIG_URI          17  /* int */

/*
** CAPI3REF: Database Connection Configuration Options
**
** These constants are the available integer configuration options that
** can be passed as the second argument to the [sqlcipher3_db_config()] interface.
**
** New configuration options may be added in future releases of SQLite.
** Existing configuration options might be discontinued.  Applications
** should check the return code from [sqlcipher3_db_config()] to make sure that
** the call worked.  ^The [sqlcipher3_db_config()] interface will return a
** non-zero [error code] if a discontinued or unsupported configuration option
** is invoked.
**
** <dl>
** <dt>SQLCIPHER_DBCONFIG_LOOKASIDE</dt>
** <dd> ^This option takes three additional arguments that determine the 
** [lookaside memory allocator] configuration for the [database connection].
** ^The first argument (the third parameter to [sqlcipher3_db_config()] is a
** pointer to a memory buffer to use for lookaside memory.
** ^The first argument after the SQLCIPHER_DBCONFIG_LOOKASIDE verb
** may be NULL in which case SQLite will allocate the
** lookaside buffer itself using [sqlcipher3_malloc()]. ^The second argument is the
** size of each lookaside buffer slot.  ^The third argument is the number of
** slots.  The size of the buffer in the first argument must be greater than
** or equal to the product of the second and third arguments.  The buffer
** must be aligned to an 8-byte boundary.  ^If the second argument to
** SQLCIPHER_DBCONFIG_LOOKASIDE is not a multiple of 8, it is internally
** rounded down to the next smaller multiple of 8.  ^(The lookaside memory
** configuration for a database connection can only be changed when that
** connection is not currently using lookaside memory, or in other words
** when the "current value" returned by
** [sqlcipher3_db_status](D,[SQLCIPHER_CONFIG_LOOKASIDE],...) is zero.
** Any attempt to change the lookaside memory configuration when lookaside
** memory is in use leaves the configuration unchanged and returns 
** [SQLCIPHER_BUSY].)^</dd>
**
** <dt>SQLCIPHER_DBCONFIG_ENABLE_FKEY</dt>
** <dd> ^This option is used to enable or disable the enforcement of
** [foreign key constraints].  There should be two additional arguments.
** The first argument is an integer which is 0 to disable FK enforcement,
** positive to enable FK enforcement or negative to leave FK enforcement
** unchanged.  The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether FK enforcement is off or on
** following this call.  The second parameter may be a NULL pointer, in
** which case the FK enforcement setting is not reported back. </dd>
**
** <dt>SQLCIPHER_DBCONFIG_ENABLE_TRIGGER</dt>
** <dd> ^This option is used to enable or disable [CREATE TRIGGER | triggers].
** There should be two additional arguments.
** The first argument is an integer which is 0 to disable triggers,
** positive to enable triggers or negative to leave the setting unchanged.
** The second parameter is a pointer to an integer into which
** is written 0 or 1 to indicate whether triggers are disabled or enabled
** following this call.  The second parameter may be a NULL pointer, in
** which case the trigger setting is not reported back. </dd>
**
** </dl>
*/
#define SQLCIPHER_DBCONFIG_LOOKASIDE       1001  /* void* int int */
#define SQLCIPHER_DBCONFIG_ENABLE_FKEY     1002  /* int int* */
#define SQLCIPHER_DBCONFIG_ENABLE_TRIGGER  1003  /* int int* */


/*
** CAPI3REF: Enable Or Disable Extended Result Codes
**
** ^The sqlcipher3_extended_result_codes() routine enables or disables the
** [extended result codes] feature of SQLite. ^The extended result
** codes are disabled by default for historical compatibility.
*/
SQLCIPHER_API int sqlcipher3_extended_result_codes(sqlcipher3*, int onoff);

/*
** CAPI3REF: Last Insert Rowid
**
** ^Each entry in an SQLite table has a unique 64-bit signed
** integer key called the [ROWID | "rowid"]. ^The rowid is always available
** as an undeclared column named ROWID, OID, or _ROWID_ as long as those
** names are not also used by explicitly declared columns. ^If
** the table has a column of type [INTEGER PRIMARY KEY] then that column
** is another alias for the rowid.
**
** ^This routine returns the [rowid] of the most recent
** successful [INSERT] into the database from the [database connection]
** in the first argument.  ^As of SQLite version 3.7.7, this routines
** records the last insert rowid of both ordinary tables and [virtual tables].
** ^If no successful [INSERT]s
** have ever occurred on that database connection, zero is returned.
**
** ^(If an [INSERT] occurs within a trigger or within a [virtual table]
** method, then this routine will return the [rowid] of the inserted
** row as long as the trigger or virtual table method is running.
** But once the trigger or virtual table method ends, the value returned 
** by this routine reverts to what it was before the trigger or virtual
** table method began.)^
**
** ^An [INSERT] that fails due to a constraint violation is not a
** successful [INSERT] and does not change the value returned by this
** routine.  ^Thus INSERT OR FAIL, INSERT OR IGNORE, INSERT OR ROLLBACK,
** and INSERT OR ABORT make no changes to the return value of this
** routine when their insertion fails.  ^(When INSERT OR REPLACE
** encounters a constraint violation, it does not fail.  The
** INSERT continues to completion after deleting rows that caused
** the constraint problem so INSERT OR REPLACE will always change
** the return value of this interface.)^
**
** ^For the purposes of this routine, an [INSERT] is considered to
** be successful even if it is subsequently rolled back.
**
** This function is accessible to SQL statements via the
** [last_insert_rowid() SQL function].
**
** If a separate thread performs a new [INSERT] on the same
** database connection while the [sqlcipher3_last_insert_rowid()]
** function is running and thus changes the last insert [rowid],
** then the value returned by [sqlcipher3_last_insert_rowid()] is
** unpredictable and might not equal either the old or the new
** last insert [rowid].
*/
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_last_insert_rowid(sqlcipher3*);

/*
** CAPI3REF: Count The Number Of Rows Modified
**
** ^This function returns the number of database rows that were changed
** or inserted or deleted by the most recently completed SQL statement
** on the [database connection] specified by the first parameter.
** ^(Only changes that are directly specified by the [INSERT], [UPDATE],
** or [DELETE] statement are counted.  Auxiliary changes caused by
** triggers or [foreign key actions] are not counted.)^ Use the
** [sqlcipher3_total_changes()] function to find the total number of changes
** including changes caused by triggers and foreign key actions.
**
** ^Changes to a view that are simulated by an [INSTEAD OF trigger]
** are not counted.  Only real table changes are counted.
**
** ^(A "row change" is a change to a single row of a single table
** caused by an INSERT, DELETE, or UPDATE statement.  Rows that
** are changed as side effects of [REPLACE] constraint resolution,
** rollback, ABORT processing, [DROP TABLE], or by any other
** mechanisms do not count as direct row changes.)^
**
** A "trigger context" is a scope of execution that begins and
** ends with the script of a [CREATE TRIGGER | trigger]. 
** Most SQL statements are
** evaluated outside of any trigger.  This is the "top level"
** trigger context.  If a trigger fires from the top level, a
** new trigger context is entered for the duration of that one
** trigger.  Subtriggers create subcontexts for their duration.
**
** ^Calling [sqlcipher3_exec()] or [sqlcipher3_step()] recursively does
** not create a new trigger context.
**
** ^This function returns the number of direct row changes in the
** most recent INSERT, UPDATE, or DELETE statement within the same
** trigger context.
**
** ^Thus, when called from the top level, this function returns the
** number of changes in the most recent INSERT, UPDATE, or DELETE
** that also occurred at the top level.  ^(Within the body of a trigger,
** the sqlcipher3_changes() interface can be called to find the number of
** changes in the most recently completed INSERT, UPDATE, or DELETE
** statement within the body of the same trigger.
** However, the number returned does not include changes
** caused by subtriggers since those have their own context.)^
**
** See also the [sqlcipher3_total_changes()] interface, the
** [count_changes pragma], and the [changes() SQL function].
**
** If a separate thread makes changes on the same database connection
** while [sqlcipher3_changes()] is running then the value returned
** is unpredictable and not meaningful.
*/
SQLCIPHER_API int sqlcipher3_changes(sqlcipher3*);

/*
** CAPI3REF: Total Number Of Rows Modified
**
** ^This function returns the number of row changes caused by [INSERT],
** [UPDATE] or [DELETE] statements since the [database connection] was opened.
** ^(The count returned by sqlcipher3_total_changes() includes all changes
** from all [CREATE TRIGGER | trigger] contexts and changes made by
** [foreign key actions]. However,
** the count does not include changes used to implement [REPLACE] constraints,
** do rollbacks or ABORT processing, or [DROP TABLE] processing.  The
** count does not include rows of views that fire an [INSTEAD OF trigger],
** though if the INSTEAD OF trigger makes changes of its own, those changes 
** are counted.)^
** ^The sqlcipher3_total_changes() function counts the changes as soon as
** the statement that makes them is completed (when the statement handle
** is passed to [sqlcipher3_reset()] or [sqlcipher3_finalize()]).
**
** See also the [sqlcipher3_changes()] interface, the
** [count_changes pragma], and the [total_changes() SQL function].
**
** If a separate thread makes changes on the same database connection
** while [sqlcipher3_total_changes()] is running then the value
** returned is unpredictable and not meaningful.
*/
SQLCIPHER_API int sqlcipher3_total_changes(sqlcipher3*);

/*
** CAPI3REF: Interrupt A Long-Running Query
**
** ^This function causes any pending database operation to abort and
** return at its earliest opportunity. This routine is typically
** called in response to a user action such as pressing "Cancel"
** or Ctrl-C where the user wants a long query operation to halt
** immediately.
**
** ^It is safe to call this routine from a thread different from the
** thread that is currently running the database operation.  But it
** is not safe to call this routine with a [database connection] that
** is closed or might close before sqlcipher3_interrupt() returns.
**
** ^If an SQL operation is very nearly finished at the time when
** sqlcipher3_interrupt() is called, then it might not have an opportunity
** to be interrupted and might continue to completion.
**
** ^An SQL operation that is interrupted will return [SQLCIPHER_INTERRUPT].
** ^If the interrupted SQL operation is an INSERT, UPDATE, or DELETE
** that is inside an explicit transaction, then the entire transaction
** will be rolled back automatically.
**
** ^The sqlcipher3_interrupt(D) call is in effect until all currently running
** SQL statements on [database connection] D complete.  ^Any new SQL statements
** that are started after the sqlcipher3_interrupt() call and before the 
** running statements reaches zero are interrupted as if they had been
** running prior to the sqlcipher3_interrupt() call.  ^New SQL statements
** that are started after the running statement count reaches zero are
** not effected by the sqlcipher3_interrupt().
** ^A call to sqlcipher3_interrupt(D) that occurs when there are no running
** SQL statements is a no-op and has no effect on SQL statements
** that are started after the sqlcipher3_interrupt() call returns.
**
** If the database connection closes while [sqlcipher3_interrupt()]
** is running then bad things will likely happen.
*/
SQLCIPHER_API void sqlcipher3_interrupt(sqlcipher3*);

/*
** CAPI3REF: Determine If An SQL Statement Is Complete
**
** These routines are useful during command-line input to determine if the
** currently entered text seems to form a complete SQL statement or
** if additional input is needed before sending the text into
** SQLite for parsing.  ^These routines return 1 if the input string
** appears to be a complete SQL statement.  ^A statement is judged to be
** complete if it ends with a semicolon token and is not a prefix of a
** well-formed CREATE TRIGGER statement.  ^Semicolons that are embedded within
** string literals or quoted identifier names or comments are not
** independent tokens (they are part of the token in which they are
** embedded) and thus do not count as a statement terminator.  ^Whitespace
** and comments that follow the final semicolon are ignored.
**
** ^These routines return 0 if the statement is incomplete.  ^If a
** memory allocation fails, then SQLCIPHER_NOMEM is returned.
**
** ^These routines do not parse the SQL statements thus
** will not detect syntactically incorrect SQL.
**
** ^(If SQLite has not been initialized using [sqlcipher3_initialize()] prior 
** to invoking sqlcipher3_complete16() then sqlcipher3_initialize() is invoked
** automatically by sqlcipher3_complete16().  If that initialization fails,
** then the return value from sqlcipher3_complete16() will be non-zero
** regardless of whether or not the input SQL is complete.)^
**
** The input to [sqlcipher3_complete()] must be a zero-terminated
** UTF-8 string.
**
** The input to [sqlcipher3_complete16()] must be a zero-terminated
** UTF-16 string in native byte order.
*/
SQLCIPHER_API int sqlcipher3_complete(const char *sql);
SQLCIPHER_API int sqlcipher3_complete16(const void *sql);

/*
** CAPI3REF: Register A Callback To Handle SQLCIPHER_BUSY Errors
**
** ^This routine sets a callback function that might be invoked whenever
** an attempt is made to open a database table that another thread
** or process has locked.
**
** ^If the busy callback is NULL, then [SQLCIPHER_BUSY] or [SQLCIPHER_IOERR_BLOCKED]
** is returned immediately upon encountering the lock.  ^If the busy callback
** is not NULL, then the callback might be invoked with two arguments.
**
** ^The first argument to the busy handler is a copy of the void* pointer which
** is the third argument to sqlcipher3_busy_handler().  ^The second argument to
** the busy handler callback is the number of times that the busy handler has
** been invoked for this locking event.  ^If the
** busy callback returns 0, then no additional attempts are made to
** access the database and [SQLCIPHER_BUSY] or [SQLCIPHER_IOERR_BLOCKED] is returned.
** ^If the callback returns non-zero, then another attempt
** is made to open the database for reading and the cycle repeats.
**
** The presence of a busy handler does not guarantee that it will be invoked
** when there is lock contention. ^If SQLite determines that invoking the busy
** handler could result in a deadlock, it will go ahead and return [SQLCIPHER_BUSY]
** or [SQLCIPHER_IOERR_BLOCKED] instead of invoking the busy handler.
** Consider a scenario where one process is holding a read lock that
** it is trying to promote to a reserved lock and
** a second process is holding a reserved lock that it is trying
** to promote to an exclusive lock.  The first process cannot proceed
** because it is blocked by the second and the second process cannot
** proceed because it is blocked by the first.  If both processes
** invoke the busy handlers, neither will make any progress.  Therefore,
** SQLite returns [SQLCIPHER_BUSY] for the first process, hoping that this
** will induce the first process to release its read lock and allow
** the second process to proceed.
**
** ^The default busy callback is NULL.
**
** ^The [SQLCIPHER_BUSY] error is converted to [SQLCIPHER_IOERR_BLOCKED]
** when SQLite is in the middle of a large transaction where all the
** changes will not fit into the in-memory cache.  SQLite will
** already hold a RESERVED lock on the database file, but it needs
** to promote this lock to EXCLUSIVE so that it can spill cache
** pages into the database file without harm to concurrent
** readers.  ^If it is unable to promote the lock, then the in-memory
** cache will be left in an inconsistent state and so the error
** code is promoted from the relatively benign [SQLCIPHER_BUSY] to
** the more severe [SQLCIPHER_IOERR_BLOCKED].  ^This error code promotion
** forces an automatic rollback of the changes.  See the
** <a href="/cvstrac/wiki?p=CorruptionFollowingBusyError">
** CorruptionFollowingBusyError</a> wiki page for a discussion of why
** this is important.
**
** ^(There can only be a single busy handler defined for each
** [database connection].  Setting a new busy handler clears any
** previously set handler.)^  ^Note that calling [sqlcipher3_busy_timeout()]
** will also set or clear the busy handler.
**
** The busy callback should not take any actions which modify the
** database connection that invoked the busy handler.  Any such actions
** result in undefined behavior.
** 
** A busy handler must not close the database connection
** or [prepared statement] that invoked the busy handler.
*/
SQLCIPHER_API int sqlcipher3_busy_handler(sqlcipher3*, int(*)(void*,int), void*);

/*
** CAPI3REF: Set A Busy Timeout
**
** ^This routine sets a [sqlcipher3_busy_handler | busy handler] that sleeps
** for a specified amount of time when a table is locked.  ^The handler
** will sleep multiple times until at least "ms" milliseconds of sleeping
** have accumulated.  ^After at least "ms" milliseconds of sleeping,
** the handler returns 0 which causes [sqlcipher3_step()] to return
** [SQLCIPHER_BUSY] or [SQLCIPHER_IOERR_BLOCKED].
**
** ^Calling this routine with an argument less than or equal to zero
** turns off all busy handlers.
**
** ^(There can only be a single busy handler for a particular
** [database connection] any any given moment.  If another busy handler
** was defined  (using [sqlcipher3_busy_handler()]) prior to calling
** this routine, that other busy handler is cleared.)^
*/
SQLCIPHER_API int sqlcipher3_busy_timeout(sqlcipher3*, int ms);

/*
** CAPI3REF: Convenience Routines For Running Queries
**
** This is a legacy interface that is preserved for backwards compatibility.
** Use of this interface is not recommended.
**
** Definition: A <b>result table</b> is memory data structure created by the
** [sqlcipher3_get_table()] interface.  A result table records the
** complete query results from one or more queries.
**
** The table conceptually has a number of rows and columns.  But
** these numbers are not part of the result table itself.  These
** numbers are obtained separately.  Let N be the number of rows
** and M be the number of columns.
**
** A result table is an array of pointers to zero-terminated UTF-8 strings.
** There are (N+1)*M elements in the array.  The first M pointers point
** to zero-terminated strings that  contain the names of the columns.
** The remaining entries all point to query results.  NULL values result
** in NULL pointers.  All other values are in their UTF-8 zero-terminated
** string representation as returned by [sqlcipher3_column_text()].
**
** A result table might consist of one or more memory allocations.
** It is not safe to pass a result table directly to [sqlcipher3_free()].
** A result table should be deallocated using [sqlcipher3_free_table()].
**
** ^(As an example of the result table format, suppose a query result
** is as follows:
**
** <blockquote><pre>
**        Name        | Age
**        -----------------------
**        Alice       | 43
**        Bob         | 28
**        Cindy       | 21
** </pre></blockquote>
**
** There are two column (M==2) and three rows (N==3).  Thus the
** result table has 8 entries.  Suppose the result table is stored
** in an array names azResult.  Then azResult holds this content:
**
** <blockquote><pre>
**        azResult&#91;0] = "Name";
**        azResult&#91;1] = "Age";
**        azResult&#91;2] = "Alice";
**        azResult&#91;3] = "43";
**        azResult&#91;4] = "Bob";
**        azResult&#91;5] = "28";
**        azResult&#91;6] = "Cindy";
**        azResult&#91;7] = "21";
** </pre></blockquote>)^
**
** ^The sqlcipher3_get_table() function evaluates one or more
** semicolon-separated SQL statements in the zero-terminated UTF-8
** string of its 2nd parameter and returns a result table to the
** pointer given in its 3rd parameter.
**
** After the application has finished with the result from sqlcipher3_get_table(),
** it must pass the result table pointer to sqlcipher3_free_table() in order to
** release the memory that was malloced.  Because of the way the
** [sqlcipher3_malloc()] happens within sqlcipher3_get_table(), the calling
** function must not try to call [sqlcipher3_free()] directly.  Only
** [sqlcipher3_free_table()] is able to release the memory properly and safely.
**
** The sqlcipher3_get_table() interface is implemented as a wrapper around
** [sqlcipher3_exec()].  The sqlcipher3_get_table() routine does not have access
** to any internal data structures of SQLite.  It uses only the public
** interface defined here.  As a consequence, errors that occur in the
** wrapper layer outside of the internal [sqlcipher3_exec()] call are not
** reflected in subsequent calls to [sqlcipher3_errcode()] or
** [sqlcipher3_errmsg()].
*/
SQLCIPHER_API int sqlcipher3_get_table(
  sqlcipher3 *db,          /* An open database */
  const char *zSql,     /* SQL to be evaluated */
  char ***pazResult,    /* Results of the query */
  int *pnRow,           /* Number of result rows written here */
  int *pnColumn,        /* Number of result columns written here */
  char **pzErrmsg       /* Error msg written here */
);
SQLCIPHER_API void sqlcipher3_free_table(char **result);

/*
** CAPI3REF: Formatted String Printing Functions
**
** These routines are work-alikes of the "printf()" family of functions
** from the standard C library.
**
** ^The sqlcipher3_mprintf() and sqlcipher3_vmprintf() routines write their
** results into memory obtained from [sqlcipher3_malloc()].
** The strings returned by these two routines should be
** released by [sqlcipher3_free()].  ^Both routines return a
** NULL pointer if [sqlcipher3_malloc()] is unable to allocate enough
** memory to hold the resulting string.
**
** ^(The sqlcipher3_snprintf() routine is similar to "snprintf()" from
** the standard C library.  The result is written into the
** buffer supplied as the second parameter whose size is given by
** the first parameter. Note that the order of the
** first two parameters is reversed from snprintf().)^  This is an
** historical accident that cannot be fixed without breaking
** backwards compatibility.  ^(Note also that sqlcipher3_snprintf()
** returns a pointer to its buffer instead of the number of
** characters actually written into the buffer.)^  We admit that
** the number of characters written would be a more useful return
** value but we cannot change the implementation of sqlcipher3_snprintf()
** now without breaking compatibility.
**
** ^As long as the buffer size is greater than zero, sqlcipher3_snprintf()
** guarantees that the buffer is always zero-terminated.  ^The first
** parameter "n" is the total size of the buffer, including space for
** the zero terminator.  So the longest string that can be completely
** written will be n-1 characters.
**
** ^The sqlcipher3_vsnprintf() routine is a varargs version of sqlcipher3_snprintf().
**
** These routines all implement some additional formatting
** options that are useful for constructing SQL statements.
** All of the usual printf() formatting options apply.  In addition, there
** is are "%q", "%Q", and "%z" options.
**
** ^(The %q option works like %s in that it substitutes a null-terminated
** string from the argument list.  But %q also doubles every '\'' character.
** %q is designed for use inside a string literal.)^  By doubling each '\''
** character it escapes that character and allows it to be inserted into
** the string.
**
** For example, assume the string variable zText contains text as follows:
**
** <blockquote><pre>
**  char *zText = "It's a happy day!";
** </pre></blockquote>
**
** One can use this text in an SQL statement as follows:
**
** <blockquote><pre>
**  char *zSQL = sqlcipher3_mprintf("INSERT INTO table VALUES('%q')", zText);
**  sqlcipher3_exec(db, zSQL, 0, 0, 0);
**  sqlcipher3_free(zSQL);
** </pre></blockquote>
**
** Because the %q format string is used, the '\'' character in zText
** is escaped and the SQL generated is as follows:
**
** <blockquote><pre>
**  INSERT INTO table1 VALUES('It''s a happy day!')
** </pre></blockquote>
**
** This is correct.  Had we used %s instead of %q, the generated SQL
** would have looked like this:
**
** <blockquote><pre>
**  INSERT INTO table1 VALUES('It's a happy day!');
** </pre></blockquote>
**
** This second example is an SQL syntax error.  As a general rule you should
** always use %q instead of %s when inserting text into a string literal.
**
** ^(The %Q option works like %q except it also adds single quotes around
** the outside of the total string.  Additionally, if the parameter in the
** argument list is a NULL pointer, %Q substitutes the text "NULL" (without
** single quotes).)^  So, for example, one could say:
**
** <blockquote><pre>
**  char *zSQL = sqlcipher3_mprintf("INSERT INTO table VALUES(%Q)", zText);
**  sqlcipher3_exec(db, zSQL, 0, 0, 0);
**  sqlcipher3_free(zSQL);
** </pre></blockquote>
**
** The code above will render a correct SQL statement in the zSQL
** variable even if the zText variable is a NULL pointer.
**
** ^(The "%z" formatting option works like "%s" but with the
** addition that after the string has been read and copied into
** the result, [sqlcipher3_free()] is called on the input string.)^
*/
SQLCIPHER_API char *sqlcipher3_mprintf(const char*,...);
SQLCIPHER_API char *sqlcipher3_vmprintf(const char*, va_list);
SQLCIPHER_API char *sqlcipher3_snprintf(int,char*,const char*, ...);
SQLCIPHER_API char *sqlcipher3_vsnprintf(int,char*,const char*, va_list);

/*
** CAPI3REF: Memory Allocation Subsystem
**
** The SQLite core uses these three routines for all of its own
** internal memory allocation needs. "Core" in the previous sentence
** does not include operating-system specific VFS implementation.  The
** Windows VFS uses native malloc() and free() for some operations.
**
** ^The sqlcipher3_malloc() routine returns a pointer to a block
** of memory at least N bytes in length, where N is the parameter.
** ^If sqlcipher3_malloc() is unable to obtain sufficient free
** memory, it returns a NULL pointer.  ^If the parameter N to
** sqlcipher3_malloc() is zero or negative then sqlcipher3_malloc() returns
** a NULL pointer.
**
** ^Calling sqlcipher3_free() with a pointer previously returned
** by sqlcipher3_malloc() or sqlcipher3_realloc() releases that memory so
** that it might be reused.  ^The sqlcipher3_free() routine is
** a no-op if is called with a NULL pointer.  Passing a NULL pointer
** to sqlcipher3_free() is harmless.  After being freed, memory
** should neither be read nor written.  Even reading previously freed
** memory might result in a segmentation fault or other severe error.
** Memory corruption, a segmentation fault, or other severe error
** might result if sqlcipher3_free() is called with a non-NULL pointer that
** was not obtained from sqlcipher3_malloc() or sqlcipher3_realloc().
**
** ^(The sqlcipher3_realloc() interface attempts to resize a
** prior memory allocation to be at least N bytes, where N is the
** second parameter.  The memory allocation to be resized is the first
** parameter.)^ ^ If the first parameter to sqlcipher3_realloc()
** is a NULL pointer then its behavior is identical to calling
** sqlcipher3_malloc(N) where N is the second parameter to sqlcipher3_realloc().
** ^If the second parameter to sqlcipher3_realloc() is zero or
** negative then the behavior is exactly the same as calling
** sqlcipher3_free(P) where P is the first parameter to sqlcipher3_realloc().
** ^sqlcipher3_realloc() returns a pointer to a memory allocation
** of at least N bytes in size or NULL if sufficient memory is unavailable.
** ^If M is the size of the prior allocation, then min(N,M) bytes
** of the prior allocation are copied into the beginning of buffer returned
** by sqlcipher3_realloc() and the prior allocation is freed.
** ^If sqlcipher3_realloc() returns NULL, then the prior allocation
** is not freed.
**
** ^The memory returned by sqlcipher3_malloc() and sqlcipher3_realloc()
** is always aligned to at least an 8 byte boundary, or to a
** 4 byte boundary if the [SQLCIPHER_4_BYTE_ALIGNED_MALLOC] compile-time
** option is used.
**
** In SQLite version 3.5.0 and 3.5.1, it was possible to define
** the SQLCIPHER_OMIT_MEMORY_ALLOCATION which would cause the built-in
** implementation of these routines to be omitted.  That capability
** is no longer provided.  Only built-in memory allocators can be used.
**
** The Windows OS interface layer calls
** the system malloc() and free() directly when converting
** filenames between the UTF-8 encoding used by SQLite
** and whatever filename encoding is used by the particular Windows
** installation.  Memory allocation errors are detected, but
** they are reported back as [SQLCIPHER_CANTOPEN] or
** [SQLCIPHER_IOERR] rather than [SQLCIPHER_NOMEM].
**
** The pointer arguments to [sqlcipher3_free()] and [sqlcipher3_realloc()]
** must be either NULL or else pointers obtained from a prior
** invocation of [sqlcipher3_malloc()] or [sqlcipher3_realloc()] that have
** not yet been released.
**
** The application must not read or write any part of
** a block of memory after it has been released using
** [sqlcipher3_free()] or [sqlcipher3_realloc()].
*/
SQLCIPHER_API void *sqlcipher3_malloc(int);
SQLCIPHER_API void *sqlcipher3_realloc(void*, int);
SQLCIPHER_API void sqlcipher3_free(void*);

/*
** CAPI3REF: Memory Allocator Statistics
**
** SQLite provides these two interfaces for reporting on the status
** of the [sqlcipher3_malloc()], [sqlcipher3_free()], and [sqlcipher3_realloc()]
** routines, which form the built-in memory allocation subsystem.
**
** ^The [sqlcipher3_memory_used()] routine returns the number of bytes
** of memory currently outstanding (malloced but not freed).
** ^The [sqlcipher3_memory_highwater()] routine returns the maximum
** value of [sqlcipher3_memory_used()] since the high-water mark
** was last reset.  ^The values returned by [sqlcipher3_memory_used()] and
** [sqlcipher3_memory_highwater()] include any overhead
** added by SQLite in its implementation of [sqlcipher3_malloc()],
** but not overhead added by the any underlying system library
** routines that [sqlcipher3_malloc()] may call.
**
** ^The memory high-water mark is reset to the current value of
** [sqlcipher3_memory_used()] if and only if the parameter to
** [sqlcipher3_memory_highwater()] is true.  ^The value returned
** by [sqlcipher3_memory_highwater(1)] is the high-water mark
** prior to the reset.
*/
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_memory_used(void);
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_memory_highwater(int resetFlag);

/*
** CAPI3REF: Pseudo-Random Number Generator
**
** SQLite contains a high-quality pseudo-random number generator (PRNG) used to
** select random [ROWID | ROWIDs] when inserting new records into a table that
** already uses the largest possible [ROWID].  The PRNG is also used for
** the build-in random() and randomblob() SQL functions.  This interface allows
** applications to access the same PRNG for other purposes.
**
** ^A call to this routine stores N bytes of randomness into buffer P.
**
** ^The first time this routine is invoked (either internally or by
** the application) the PRNG is seeded using randomness obtained
** from the xRandomness method of the default [sqlcipher3_vfs] object.
** ^On all subsequent invocations, the pseudo-randomness is generated
** internally and without recourse to the [sqlcipher3_vfs] xRandomness
** method.
*/
SQLCIPHER_API void sqlcipher3_randomness(int N, void *P);

/*
** CAPI3REF: Compile-Time Authorization Callbacks
**
** ^This routine registers an authorizer callback with a particular
** [database connection], supplied in the first argument.
** ^The authorizer callback is invoked as SQL statements are being compiled
** by [sqlcipher3_prepare()] or its variants [sqlcipher3_prepare_v2()],
** [sqlcipher3_prepare16()] and [sqlcipher3_prepare16_v2()].  ^At various
** points during the compilation process, as logic is being created
** to perform various actions, the authorizer callback is invoked to
** see if those actions are allowed.  ^The authorizer callback should
** return [SQLCIPHER_OK] to allow the action, [SQLCIPHER_IGNORE] to disallow the
** specific action but allow the SQL statement to continue to be
** compiled, or [SQLCIPHER_DENY] to cause the entire SQL statement to be
** rejected with an error.  ^If the authorizer callback returns
** any value other than [SQLCIPHER_IGNORE], [SQLCIPHER_OK], or [SQLCIPHER_DENY]
** then the [sqlcipher3_prepare_v2()] or equivalent call that triggered
** the authorizer will fail with an error message.
**
** When the callback returns [SQLCIPHER_OK], that means the operation
** requested is ok.  ^When the callback returns [SQLCIPHER_DENY], the
** [sqlcipher3_prepare_v2()] or equivalent call that triggered the
** authorizer will fail with an error message explaining that
** access is denied. 
**
** ^The first parameter to the authorizer callback is a copy of the third
** parameter to the sqlcipher3_set_authorizer() interface. ^The second parameter
** to the callback is an integer [SQLCIPHER_COPY | action code] that specifies
** the particular action to be authorized. ^The third through sixth parameters
** to the callback are zero-terminated strings that contain additional
** details about the action to be authorized.
**
** ^If the action code is [SQLCIPHER_READ]
** and the callback returns [SQLCIPHER_IGNORE] then the
** [prepared statement] statement is constructed to substitute
** a NULL value in place of the table column that would have
** been read if [SQLCIPHER_OK] had been returned.  The [SQLCIPHER_IGNORE]
** return can be used to deny an untrusted user access to individual
** columns of a table.
** ^If the action code is [SQLCIPHER_DELETE] and the callback returns
** [SQLCIPHER_IGNORE] then the [DELETE] operation proceeds but the
** [truncate optimization] is disabled and all rows are deleted individually.
**
** An authorizer is used when [sqlcipher3_prepare | preparing]
** SQL statements from an untrusted source, to ensure that the SQL statements
** do not try to access data they are not allowed to see, or that they do not
** try to execute malicious statements that damage the database.  For
** example, an application may allow a user to enter arbitrary
** SQL queries for evaluation by a database.  But the application does
** not want the user to be able to make arbitrary changes to the
** database.  An authorizer could then be put in place while the
** user-entered SQL is being [sqlcipher3_prepare | prepared] that
** disallows everything except [SELECT] statements.
**
** Applications that need to process SQL from untrusted sources
** might also consider lowering resource limits using [sqlcipher3_limit()]
** and limiting database size using the [max_page_count] [PRAGMA]
** in addition to using an authorizer.
**
** ^(Only a single authorizer can be in place on a database connection
** at a time.  Each call to sqlcipher3_set_authorizer overrides the
** previous call.)^  ^Disable the authorizer by installing a NULL callback.
** The authorizer is disabled by default.
**
** The authorizer callback must not do anything that will modify
** the database connection that invoked the authorizer callback.
** Note that [sqlcipher3_prepare_v2()] and [sqlcipher3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
** ^When [sqlcipher3_prepare_v2()] is used to prepare a statement, the
** statement might be re-prepared during [sqlcipher3_step()] due to a 
** schema change.  Hence, the application should ensure that the
** correct authorizer callback remains in place during the [sqlcipher3_step()].
**
** ^Note that the authorizer callback is invoked only during
** [sqlcipher3_prepare()] or its variants.  Authorization is not
** performed during statement evaluation in [sqlcipher3_step()], unless
** as stated in the previous paragraph, sqlcipher3_step() invokes
** sqlcipher3_prepare_v2() to reprepare a statement after a schema change.
*/
SQLCIPHER_API int sqlcipher3_set_authorizer(
  sqlcipher3*,
  int (*xAuth)(void*,int,const char*,const char*,const char*,const char*),
  void *pUserData
);

/*
** CAPI3REF: Authorizer Return Codes
**
** The [sqlcipher3_set_authorizer | authorizer callback function] must
** return either [SQLCIPHER_OK] or one of these two constants in order
** to signal SQLite whether or not the action is permitted.  See the
** [sqlcipher3_set_authorizer | authorizer documentation] for additional
** information.
**
** Note that SQLCIPHER_IGNORE is also used as a [SQLCIPHER_ROLLBACK | return code]
** from the [sqlcipher3_vtab_on_conflict()] interface.
*/
#define SQLCIPHER_DENY   1   /* Abort the SQL statement with an error */
#define SQLCIPHER_IGNORE 2   /* Don't allow access, but don't generate an error */

/*
** CAPI3REF: Authorizer Action Codes
**
** The [sqlcipher3_set_authorizer()] interface registers a callback function
** that is invoked to authorize certain SQL statement actions.  The
** second parameter to the callback is an integer code that specifies
** what action is being authorized.  These are the integer action codes that
** the authorizer callback may be passed.
**
** These action code values signify what kind of operation is to be
** authorized.  The 3rd and 4th parameters to the authorization
** callback function will be parameters or NULL depending on which of these
** codes is used as the second parameter.  ^(The 5th parameter to the
** authorizer callback is the name of the database ("main", "temp",
** etc.) if applicable.)^  ^The 6th parameter to the authorizer callback
** is the name of the inner-most trigger or view that is responsible for
** the access attempt or NULL if this access attempt is directly from
** top-level SQL code.
*/
/******************************************* 3rd ************ 4th ***********/
#define SQLCIPHER_CREATE_INDEX          1   /* Index Name      Table Name      */
#define SQLCIPHER_CREATE_TABLE          2   /* Table Name      NULL            */
#define SQLCIPHER_CREATE_TEMP_INDEX     3   /* Index Name      Table Name      */
#define SQLCIPHER_CREATE_TEMP_TABLE     4   /* Table Name      NULL            */
#define SQLCIPHER_CREATE_TEMP_TRIGGER   5   /* Trigger Name    Table Name      */
#define SQLCIPHER_CREATE_TEMP_VIEW      6   /* View Name       NULL            */
#define SQLCIPHER_CREATE_TRIGGER        7   /* Trigger Name    Table Name      */
#define SQLCIPHER_CREATE_VIEW           8   /* View Name       NULL            */
#define SQLCIPHER_DELETE                9   /* Table Name      NULL            */
#define SQLCIPHER_DROP_INDEX           10   /* Index Name      Table Name      */
#define SQLCIPHER_DROP_TABLE           11   /* Table Name      NULL            */
#define SQLCIPHER_DROP_TEMP_INDEX      12   /* Index Name      Table Name      */
#define SQLCIPHER_DROP_TEMP_TABLE      13   /* Table Name      NULL            */
#define SQLCIPHER_DROP_TEMP_TRIGGER    14   /* Trigger Name    Table Name      */
#define SQLCIPHER_DROP_TEMP_VIEW       15   /* View Name       NULL            */
#define SQLCIPHER_DROP_TRIGGER         16   /* Trigger Name    Table Name      */
#define SQLCIPHER_DROP_VIEW            17   /* View Name       NULL            */
#define SQLCIPHER_INSERT               18   /* Table Name      NULL            */
#define SQLCIPHER_PRAGMA               19   /* Pragma Name     1st arg or NULL */
#define SQLCIPHER_READ                 20   /* Table Name      Column Name     */
#define SQLCIPHER_SELECT               21   /* NULL            NULL            */
#define SQLCIPHER_TRANSACTION          22   /* Operation       NULL            */
#define SQLCIPHER_UPDATE               23   /* Table Name      Column Name     */
#define SQLCIPHER_ATTACH               24   /* Filename        NULL            */
#define SQLCIPHER_DETACH               25   /* Database Name   NULL            */
#define SQLCIPHER_ALTER_TABLE          26   /* Database Name   Table Name      */
#define SQLCIPHER_REINDEX              27   /* Index Name      NULL            */
#define SQLCIPHER_ANALYZE              28   /* Table Name      NULL            */
#define SQLCIPHER_CREATE_VTABLE        29   /* Table Name      Module Name     */
#define SQLCIPHER_DROP_VTABLE          30   /* Table Name      Module Name     */
#define SQLCIPHER_FUNCTION             31   /* NULL            Function Name   */
#define SQLCIPHER_SAVEPOINT            32   /* Operation       Savepoint Name  */
#define SQLCIPHER_COPY                  0   /* No longer used */

/*
** CAPI3REF: Tracing And Profiling Functions
**
** These routines register callback functions that can be used for
** tracing and profiling the execution of SQL statements.
**
** ^The callback function registered by sqlcipher3_trace() is invoked at
** various times when an SQL statement is being run by [sqlcipher3_step()].
** ^The sqlcipher3_trace() callback is invoked with a UTF-8 rendering of the
** SQL statement text as the statement first begins executing.
** ^(Additional sqlcipher3_trace() callbacks might occur
** as each triggered subprogram is entered.  The callbacks for triggers
** contain a UTF-8 SQL comment that identifies the trigger.)^
**
** ^The callback function registered by sqlcipher3_profile() is invoked
** as each SQL statement finishes.  ^The profile callback contains
** the original statement text and an estimate of wall-clock time
** of how long that statement took to run.  ^The profile callback
** time is in units of nanoseconds, however the current implementation
** is only capable of millisecond resolution so the six least significant
** digits in the time are meaningless.  Future versions of SQLite
** might provide greater resolution on the profiler callback.  The
** sqlcipher3_profile() function is considered experimental and is
** subject to change in future versions of SQLite.
*/
SQLCIPHER_API void *sqlcipher3_trace(sqlcipher3*, void(*xTrace)(void*,const char*), void*);
SQLCIPHER_API SQLCIPHER_EXPERIMENTAL void *sqlcipher3_profile(sqlcipher3*,
   void(*xProfile)(void*,const char*,sqlcipher3_uint64), void*);

/*
** CAPI3REF: Query Progress Callbacks
**
** ^The sqlcipher3_progress_handler(D,N,X,P) interface causes the callback
** function X to be invoked periodically during long running calls to
** [sqlcipher3_exec()], [sqlcipher3_step()] and [sqlcipher3_get_table()] for
** database connection D.  An example use for this
** interface is to keep a GUI updated during a large query.
**
** ^The parameter P is passed through as the only parameter to the 
** callback function X.  ^The parameter N is the number of 
** [virtual machine instructions] that are evaluated between successive
** invocations of the callback X.
**
** ^Only a single progress handler may be defined at one time per
** [database connection]; setting a new progress handler cancels the
** old one.  ^Setting parameter X to NULL disables the progress handler.
** ^The progress handler is also disabled by setting N to a value less
** than 1.
**
** ^If the progress callback returns non-zero, the operation is
** interrupted.  This feature can be used to implement a
** "Cancel" button on a GUI progress dialog box.
**
** The progress handler callback must not do anything that will modify
** the database connection that invoked the progress handler.
** Note that [sqlcipher3_prepare_v2()] and [sqlcipher3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
*/
SQLCIPHER_API void sqlcipher3_progress_handler(sqlcipher3*, int, int(*)(void*), void*);

/*
** CAPI3REF: Opening A New Database Connection
**
** ^These routines open an SQLite database file as specified by the 
** filename argument. ^The filename argument is interpreted as UTF-8 for
** sqlcipher3_open() and sqlcipher3_open_v2() and as UTF-16 in the native byte
** order for sqlcipher3_open16(). ^(A [database connection] handle is usually
** returned in *ppDb, even if an error occurs.  The only exception is that
** if SQLite is unable to allocate memory to hold the [sqlcipher3] object,
** a NULL will be written into *ppDb instead of a pointer to the [sqlcipher3]
** object.)^ ^(If the database is opened (and/or created) successfully, then
** [SQLCIPHER_OK] is returned.  Otherwise an [error code] is returned.)^ ^The
** [sqlcipher3_errmsg()] or [sqlcipher3_errmsg16()] routines can be used to obtain
** an English language description of the error following a failure of any
** of the sqlcipher3_open() routines.
**
** ^The default encoding for the database will be UTF-8 if
** sqlcipher3_open() or sqlcipher3_open_v2() is called and
** UTF-16 in the native byte order if sqlcipher3_open16() is used.
**
** Whether or not an error occurs when it is opened, resources
** associated with the [database connection] handle should be released by
** passing it to [sqlcipher3_close()] when it is no longer required.
**
** The sqlcipher3_open_v2() interface works like sqlcipher3_open()
** except that it accepts two additional parameters for additional control
** over the new database connection.  ^(The flags parameter to
** sqlcipher3_open_v2() can take one of
** the following three values, optionally combined with the 
** [SQLCIPHER_OPEN_NOMUTEX], [SQLCIPHER_OPEN_FULLMUTEX], [SQLCIPHER_OPEN_SHAREDCACHE],
** [SQLCIPHER_OPEN_PRIVATECACHE], and/or [SQLCIPHER_OPEN_URI] flags:)^
**
** <dl>
** ^(<dt>[SQLCIPHER_OPEN_READONLY]</dt>
** <dd>The database is opened in read-only mode.  If the database does not
** already exist, an error is returned.</dd>)^
**
** ^(<dt>[SQLCIPHER_OPEN_READWRITE]</dt>
** <dd>The database is opened for reading and writing if possible, or reading
** only if the file is write protected by the operating system.  In either
** case the database must already exist, otherwise an error is returned.</dd>)^
**
** ^(<dt>[SQLCIPHER_OPEN_READWRITE] | [SQLCIPHER_OPEN_CREATE]</dt>
** <dd>The database is opened for reading and writing, and is created if
** it does not already exist. This is the behavior that is always used for
** sqlcipher3_open() and sqlcipher3_open16().</dd>)^
** </dl>
**
** If the 3rd parameter to sqlcipher3_open_v2() is not one of the
** combinations shown above optionally combined with other
** [SQLCIPHER_OPEN_READONLY | SQLCIPHER_OPEN_* bits]
** then the behavior is undefined.
**
** ^If the [SQLCIPHER_OPEN_NOMUTEX] flag is set, then the database connection
** opens in the multi-thread [threading mode] as long as the single-thread
** mode has not been set at compile-time or start-time.  ^If the
** [SQLCIPHER_OPEN_FULLMUTEX] flag is set then the database connection opens
** in the serialized [threading mode] unless single-thread was
** previously selected at compile-time or start-time.
** ^The [SQLCIPHER_OPEN_SHAREDCACHE] flag causes the database connection to be
** eligible to use [shared cache mode], regardless of whether or not shared
** cache is enabled using [sqlcipher3_enable_shared_cache()].  ^The
** [SQLCIPHER_OPEN_PRIVATECACHE] flag causes the database connection to not
** participate in [shared cache mode] even if it is enabled.
**
** ^The fourth parameter to sqlcipher3_open_v2() is the name of the
** [sqlcipher3_vfs] object that defines the operating system interface that
** the new database connection should use.  ^If the fourth parameter is
** a NULL pointer then the default [sqlcipher3_vfs] object is used.
**
** ^If the filename is ":memory:", then a private, temporary in-memory database
** is created for the connection.  ^This in-memory database will vanish when
** the database connection is closed.  Future versions of SQLite might
** make use of additional special filenames that begin with the ":" character.
** It is recommended that when a database filename actually does begin with
** a ":" character you should prefix the filename with a pathname such as
** "./" to avoid ambiguity.
**
** ^If the filename is an empty string, then a private, temporary
** on-disk database will be created.  ^This private database will be
** automatically deleted as soon as the database connection is closed.
**
** [[URI filenames in sqlcipher3_open()]] <h3>URI Filenames</h3>
**
** ^If [URI filename] interpretation is enabled, and the filename argument
** begins with "file:", then the filename is interpreted as a URI. ^URI
** filename interpretation is enabled if the [SQLCIPHER_OPEN_URI] flag is
** set in the fourth argument to sqlcipher3_open_v2(), or if it has
** been enabled globally using the [SQLCIPHER_CONFIG_URI] option with the
** [sqlcipher3_config()] method or by the [SQLCIPHER_USE_URI] compile-time option.
** As of SQLite version 3.7.7, URI filename interpretation is turned off
** by default, but future releases of SQLite might enable URI filename
** interpretation by default.  See "[URI filenames]" for additional
** information.
**
** URI filenames are parsed according to RFC 3986. ^If the URI contains an
** authority, then it must be either an empty string or the string 
** "localhost". ^If the authority is not an empty string or "localhost", an 
** error is returned to the caller. ^The fragment component of a URI, if 
** present, is ignored.
**
** ^SQLite uses the path component of the URI as the name of the disk file
** which contains the database. ^If the path begins with a '/' character, 
** then it is interpreted as an absolute path. ^If the path does not begin 
** with a '/' (meaning that the authority section is omitted from the URI)
** then the path is interpreted as a relative path. 
** ^On windows, the first component of an absolute path 
** is a drive specification (e.g. "C:").
**
** [[core URI query parameters]]
** The query component of a URI may contain parameters that are interpreted
** either by SQLite itself, or by a [VFS | custom VFS implementation].
** SQLite interprets the following three query parameters:
**
** <ul>
**   <li> <b>vfs</b>: ^The "vfs" parameter may be used to specify the name of
**     a VFS object that provides the operating system interface that should
**     be used to access the database file on disk. ^If this option is set to
**     an empty string the default VFS object is used. ^Specifying an unknown
**     VFS is an error. ^If sqlcipher3_open_v2() is used and the vfs option is
**     present, then the VFS specified by the option takes precedence over
**     the value passed as the fourth parameter to sqlcipher3_open_v2().
**
**   <li> <b>mode</b>: ^(The mode parameter may be set to either "ro", "rw" or
**     "rwc". Attempting to set it to any other value is an error)^. 
**     ^If "ro" is specified, then the database is opened for read-only 
**     access, just as if the [SQLCIPHER_OPEN_READONLY] flag had been set in the 
**     third argument to sqlcipher3_prepare_v2(). ^If the mode option is set to 
**     "rw", then the database is opened for read-write (but not create) 
**     access, as if SQLCIPHER_OPEN_READWRITE (but not SQLCIPHER_OPEN_CREATE) had 
**     been set. ^Value "rwc" is equivalent to setting both 
**     SQLCIPHER_OPEN_READWRITE and SQLCIPHER_OPEN_CREATE. ^If sqlcipher3_open_v2() is 
**     used, it is an error to specify a value for the mode parameter that is 
**     less restrictive than that specified by the flags passed as the third 
**     parameter.
**
**   <li> <b>cache</b>: ^The cache parameter may be set to either "shared" or
**     "private". ^Setting it to "shared" is equivalent to setting the
**     SQLCIPHER_OPEN_SHAREDCACHE bit in the flags argument passed to
**     sqlcipher3_open_v2(). ^Setting the cache parameter to "private" is 
**     equivalent to setting the SQLCIPHER_OPEN_PRIVATECACHE bit.
**     ^If sqlcipher3_open_v2() is used and the "cache" parameter is present in
**     a URI filename, its value overrides any behaviour requested by setting
**     SQLCIPHER_OPEN_PRIVATECACHE or SQLCIPHER_OPEN_SHAREDCACHE flag.
** </ul>
**
** ^Specifying an unknown parameter in the query component of a URI is not an
** error.  Future versions of SQLite might understand additional query
** parameters.  See "[query parameters with special meaning to SQLite]" for
** additional information.
**
** [[URI filename examples]] <h3>URI filename examples</h3>
**
** <table border="1" align=center cellpadding=5>
** <tr><th> URI filenames <th> Results
** <tr><td> file:data.db <td> 
**          Open the file "data.db" in the current directory.
** <tr><td> file:/home/fred/data.db<br>
**          file:///home/fred/data.db <br> 
**          file://localhost/home/fred/data.db <br> <td> 
**          Open the database file "/home/fred/data.db".
** <tr><td> file://darkstar/home/fred/data.db <td> 
**          An error. "darkstar" is not a recognized authority.
** <tr><td style="white-space:nowrap"> 
**          file:///C:/Documents%20and%20Settings/fred/Desktop/data.db
**     <td> Windows only: Open the file "data.db" on fred's desktop on drive
**          C:. Note that the %20 escaping in this example is not strictly 
**          necessary - space characters can be used literally
**          in URI filenames.
** <tr><td> file:data.db?mode=ro&cache=private <td> 
**          Open file "data.db" in the current directory for read-only access.
**          Regardless of whether or not shared-cache mode is enabled by
**          default, use a private cache.
** <tr><td> file:/home/fred/data.db?vfs=unix-nolock <td>
**          Open file "/home/fred/data.db". Use the special VFS "unix-nolock".
** <tr><td> file:data.db?mode=readonly <td> 
**          An error. "readonly" is not a valid option for the "mode" parameter.
** </table>
**
** ^URI hexadecimal escape sequences (%HH) are supported within the path and
** query components of a URI. A hexadecimal escape sequence consists of a
** percent sign - "%" - followed by exactly two hexadecimal digits 
** specifying an octet value. ^Before the path or query components of a
** URI filename are interpreted, they are encoded using UTF-8 and all 
** hexadecimal escape sequences replaced by a single byte containing the
** corresponding octet. If this process generates an invalid UTF-8 encoding,
** the results are undefined.
**
** <b>Note to Windows users:</b>  The encoding used for the filename argument
** of sqlcipher3_open() and sqlcipher3_open_v2() must be UTF-8, not whatever
** codepage is currently defined.  Filenames containing international
** characters must be converted to UTF-8 prior to passing them into
** sqlcipher3_open() or sqlcipher3_open_v2().
*/
SQLCIPHER_API int sqlcipher3_open(
  const char *filename,   /* Database filename (UTF-8) */
  sqlcipher3 **ppDb          /* OUT: SQLite db handle */
);
SQLCIPHER_API int sqlcipher3_open16(
  const void *filename,   /* Database filename (UTF-16) */
  sqlcipher3 **ppDb          /* OUT: SQLite db handle */
);
SQLCIPHER_API int sqlcipher3_open_v2(
  const char *filename,   /* Database filename (UTF-8) */
  sqlcipher3 **ppDb,         /* OUT: SQLite db handle */
  int flags,              /* Flags */
  const char *zVfs        /* Name of VFS module to use */
);

/*
** CAPI3REF: Obtain Values For URI Parameters
**
** This is a utility routine, useful to VFS implementations, that checks
** to see if a database file was a URI that contained a specific query 
** parameter, and if so obtains the value of the query parameter.
**
** The zFilename argument is the filename pointer passed into the xOpen()
** method of a VFS implementation.  The zParam argument is the name of the
** query parameter we seek.  This routine returns the value of the zParam
** parameter if it exists.  If the parameter does not exist, this routine
** returns a NULL pointer.
**
** If the zFilename argument to this function is not a pointer that SQLite
** passed into the xOpen VFS method, then the behavior of this routine
** is undefined and probably undesirable.
*/
SQLCIPHER_API const char *sqlcipher3_uri_parameter(const char *zFilename, const char *zParam);


/*
** CAPI3REF: Error Codes And Messages
**
** ^The sqlcipher3_errcode() interface returns the numeric [result code] or
** [extended result code] for the most recent failed sqlcipher3_* API call
** associated with a [database connection]. If a prior API call failed
** but the most recent API call succeeded, the return value from
** sqlcipher3_errcode() is undefined.  ^The sqlcipher3_extended_errcode()
** interface is the same except that it always returns the 
** [extended result code] even when extended result codes are
** disabled.
**
** ^The sqlcipher3_errmsg() and sqlcipher3_errmsg16() return English-language
** text that describes the error, as either UTF-8 or UTF-16 respectively.
** ^(Memory to hold the error message string is managed internally.
** The application does not need to worry about freeing the result.
** However, the error string might be overwritten or deallocated by
** subsequent calls to other SQLite interface functions.)^
**
** When the serialized [threading mode] is in use, it might be the
** case that a second error occurs on a separate thread in between
** the time of the first error and the call to these interfaces.
** When that happens, the second error will be reported since these
** interfaces always report the most recent result.  To avoid
** this, each thread can obtain exclusive use of the [database connection] D
** by invoking [sqlcipher3_mutex_enter]([sqlcipher3_db_mutex](D)) before beginning
** to use D and invoking [sqlcipher3_mutex_leave]([sqlcipher3_db_mutex](D)) after
** all calls to the interfaces listed here are completed.
**
** If an interface fails with SQLCIPHER_MISUSE, that means the interface
** was invoked incorrectly by the application.  In that case, the
** error code and message may or may not be set.
*/
SQLCIPHER_API int sqlcipher3_errcode(sqlcipher3 *db);
SQLCIPHER_API int sqlcipher3_extended_errcode(sqlcipher3 *db);
SQLCIPHER_API const char *sqlcipher3_errmsg(sqlcipher3*);
SQLCIPHER_API const void *sqlcipher3_errmsg16(sqlcipher3*);

/*
** CAPI3REF: SQL Statement Object
** KEYWORDS: {prepared statement} {prepared statements}
**
** An instance of this object represents a single SQL statement.
** This object is variously known as a "prepared statement" or a
** "compiled SQL statement" or simply as a "statement".
**
** The life of a statement object goes something like this:
**
** <ol>
** <li> Create the object using [sqlcipher3_prepare_v2()] or a related
**      function.
** <li> Bind values to [host parameters] using the sqlcipher3_bind_*()
**      interfaces.
** <li> Run the SQL by calling [sqlcipher3_step()] one or more times.
** <li> Reset the statement using [sqlcipher3_reset()] then go back
**      to step 2.  Do this zero or more times.
** <li> Destroy the object using [sqlcipher3_finalize()].
** </ol>
**
** Refer to documentation on individual methods above for additional
** information.
*/
typedef struct sqlcipher3_stmt sqlcipher3_stmt;

/*
** CAPI3REF: Run-time Limits
**
** ^(This interface allows the size of various constructs to be limited
** on a connection by connection basis.  The first parameter is the
** [database connection] whose limit is to be set or queried.  The
** second parameter is one of the [limit categories] that define a
** class of constructs to be size limited.  The third parameter is the
** new limit for that construct.)^
**
** ^If the new limit is a negative number, the limit is unchanged.
** ^(For each limit category SQLCIPHER_LIMIT_<i>NAME</i> there is a 
** [limits | hard upper bound]
** set at compile-time by a C preprocessor macro called
** [limits | SQLCIPHER_MAX_<i>NAME</i>].
** (The "_LIMIT_" in the name is changed to "_MAX_".))^
** ^Attempts to increase a limit above its hard upper bound are
** silently truncated to the hard upper bound.
**
** ^Regardless of whether or not the limit was changed, the 
** [sqlcipher3_limit()] interface returns the prior value of the limit.
** ^Hence, to find the current value of a limit without changing it,
** simply invoke this interface with the third parameter set to -1.
**
** Run-time limits are intended for use in applications that manage
** both their own internal database and also databases that are controlled
** by untrusted external sources.  An example application might be a
** web browser that has its own databases for storing history and
** separate databases controlled by JavaScript applications downloaded
** off the Internet.  The internal databases can be given the
** large, default limits.  Databases managed by external sources can
** be given much smaller limits designed to prevent a denial of service
** attack.  Developers might also want to use the [sqlcipher3_set_authorizer()]
** interface to further control untrusted SQL.  The size of the database
** created by an untrusted script can be contained using the
** [max_page_count] [PRAGMA].
**
** New run-time limit categories may be added in future releases.
*/
SQLCIPHER_API int sqlcipher3_limit(sqlcipher3*, int id, int newVal);

/*
** CAPI3REF: Run-Time Limit Categories
** KEYWORDS: {limit category} {*limit categories}
**
** These constants define various performance limits
** that can be lowered at run-time using [sqlcipher3_limit()].
** The synopsis of the meanings of the various limits is shown below.
** Additional information is available at [limits | Limits in SQLite].
**
** <dl>
** [[SQLCIPHER_LIMIT_LENGTH]] ^(<dt>SQLCIPHER_LIMIT_LENGTH</dt>
** <dd>The maximum size of any string or BLOB or table row, in bytes.<dd>)^
**
** [[SQLCIPHER_LIMIT_SQL_LENGTH]] ^(<dt>SQLCIPHER_LIMIT_SQL_LENGTH</dt>
** <dd>The maximum length of an SQL statement, in bytes.</dd>)^
**
** [[SQLCIPHER_LIMIT_COLUMN]] ^(<dt>SQLCIPHER_LIMIT_COLUMN</dt>
** <dd>The maximum number of columns in a table definition or in the
** result set of a [SELECT] or the maximum number of columns in an index
** or in an ORDER BY or GROUP BY clause.</dd>)^
**
** [[SQLCIPHER_LIMIT_EXPR_DEPTH]] ^(<dt>SQLCIPHER_LIMIT_EXPR_DEPTH</dt>
** <dd>The maximum depth of the parse tree on any expression.</dd>)^
**
** [[SQLCIPHER_LIMIT_COMPOUND_SELECT]] ^(<dt>SQLCIPHER_LIMIT_COMPOUND_SELECT</dt>
** <dd>The maximum number of terms in a compound SELECT statement.</dd>)^
**
** [[SQLCIPHER_LIMIT_VDBE_OP]] ^(<dt>SQLCIPHER_LIMIT_VDBE_OP</dt>
** <dd>The maximum number of instructions in a virtual machine program
** used to implement an SQL statement.  This limit is not currently
** enforced, though that might be added in some future release of
** SQLite.</dd>)^
**
** [[SQLCIPHER_LIMIT_FUNCTION_ARG]] ^(<dt>SQLCIPHER_LIMIT_FUNCTION_ARG</dt>
** <dd>The maximum number of arguments on a function.</dd>)^
**
** [[SQLCIPHER_LIMIT_ATTACHED]] ^(<dt>SQLCIPHER_LIMIT_ATTACHED</dt>
** <dd>The maximum number of [ATTACH | attached databases].)^</dd>
**
** [[SQLCIPHER_LIMIT_LIKE_PATTERN_LENGTH]]
** ^(<dt>SQLCIPHER_LIMIT_LIKE_PATTERN_LENGTH</dt>
** <dd>The maximum length of the pattern argument to the [LIKE] or
** [GLOB] operators.</dd>)^
**
** [[SQLCIPHER_LIMIT_VARIABLE_NUMBER]]
** ^(<dt>SQLCIPHER_LIMIT_VARIABLE_NUMBER</dt>
** <dd>The maximum index number of any [parameter] in an SQL statement.)^
**
** [[SQLCIPHER_LIMIT_TRIGGER_DEPTH]] ^(<dt>SQLCIPHER_LIMIT_TRIGGER_DEPTH</dt>
** <dd>The maximum depth of recursion for triggers.</dd>)^
** </dl>
*/
#define SQLCIPHER_LIMIT_LENGTH                    0
#define SQLCIPHER_LIMIT_SQL_LENGTH                1
#define SQLCIPHER_LIMIT_COLUMN                    2
#define SQLCIPHER_LIMIT_EXPR_DEPTH                3
#define SQLCIPHER_LIMIT_COMPOUND_SELECT           4
#define SQLCIPHER_LIMIT_VDBE_OP                   5
#define SQLCIPHER_LIMIT_FUNCTION_ARG              6
#define SQLCIPHER_LIMIT_ATTACHED                  7
#define SQLCIPHER_LIMIT_LIKE_PATTERN_LENGTH       8
#define SQLCIPHER_LIMIT_VARIABLE_NUMBER           9
#define SQLCIPHER_LIMIT_TRIGGER_DEPTH            10

/*
** CAPI3REF: Compiling An SQL Statement
** KEYWORDS: {SQL statement compiler}
**
** To execute an SQL query, it must first be compiled into a byte-code
** program using one of these routines.
**
** The first argument, "db", is a [database connection] obtained from a
** prior successful call to [sqlcipher3_open()], [sqlcipher3_open_v2()] or
** [sqlcipher3_open16()].  The database connection must not have been closed.
**
** The second argument, "zSql", is the statement to be compiled, encoded
** as either UTF-8 or UTF-16.  The sqlcipher3_prepare() and sqlcipher3_prepare_v2()
** interfaces use UTF-8, and sqlcipher3_prepare16() and sqlcipher3_prepare16_v2()
** use UTF-16.
**
** ^If the nByte argument is less than zero, then zSql is read up to the
** first zero terminator. ^If nByte is non-negative, then it is the maximum
** number of  bytes read from zSql.  ^When nByte is non-negative, the
** zSql string ends at either the first '\000' or '\u0000' character or
** the nByte-th byte, whichever comes first. If the caller knows
** that the supplied string is nul-terminated, then there is a small
** performance advantage to be gained by passing an nByte parameter that
** is equal to the number of bytes in the input string <i>including</i>
** the nul-terminator bytes as this saves SQLite from having to
** make a copy of the input string.
**
** ^If pzTail is not NULL then *pzTail is made to point to the first byte
** past the end of the first SQL statement in zSql.  These routines only
** compile the first statement in zSql, so *pzTail is left pointing to
** what remains uncompiled.
**
** ^*ppStmt is left pointing to a compiled [prepared statement] that can be
** executed using [sqlcipher3_step()].  ^If there is an error, *ppStmt is set
** to NULL.  ^If the input text contains no SQL (if the input is an empty
** string or a comment) then *ppStmt is set to NULL.
** The calling procedure is responsible for deleting the compiled
** SQL statement using [sqlcipher3_finalize()] after it has finished with it.
** ppStmt may not be NULL.
**
** ^On success, the sqlcipher3_prepare() family of routines return [SQLCIPHER_OK];
** otherwise an [error code] is returned.
**
** The sqlcipher3_prepare_v2() and sqlcipher3_prepare16_v2() interfaces are
** recommended for all new programs. The two older interfaces are retained
** for backwards compatibility, but their use is discouraged.
** ^In the "v2" interfaces, the prepared statement
** that is returned (the [sqlcipher3_stmt] object) contains a copy of the
** original SQL text. This causes the [sqlcipher3_step()] interface to
** behave differently in three ways:
**
** <ol>
** <li>
** ^If the database schema changes, instead of returning [SQLCIPHER_SCHEMA] as it
** always used to do, [sqlcipher3_step()] will automatically recompile the SQL
** statement and try to run it again.
** </li>
**
** <li>
** ^When an error occurs, [sqlcipher3_step()] will return one of the detailed
** [error codes] or [extended error codes].  ^The legacy behavior was that
** [sqlcipher3_step()] would only return a generic [SQLCIPHER_ERROR] result code
** and the application would have to make a second call to [sqlcipher3_reset()]
** in order to find the underlying cause of the problem. With the "v2" prepare
** interfaces, the underlying reason for the error is returned immediately.
** </li>
**
** <li>
** ^If the specific value bound to [parameter | host parameter] in the 
** WHERE clause might influence the choice of query plan for a statement,
** then the statement will be automatically recompiled, as if there had been 
** a schema change, on the first  [sqlcipher3_step()] call following any change
** to the [sqlcipher3_bind_text | bindings] of that [parameter]. 
** ^The specific value of WHERE-clause [parameter] might influence the 
** choice of query plan if the parameter is the left-hand side of a [LIKE]
** or [GLOB] operator or if the parameter is compared to an indexed column
** and the [SQLCIPHER_ENABLE_STAT3] compile-time option is enabled.
** the 
** </li>
** </ol>
*/
SQLCIPHER_API int sqlcipher3_prepare(
  sqlcipher3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlcipher3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLCIPHER_API int sqlcipher3_prepare_v2(
  sqlcipher3 *db,            /* Database handle */
  const char *zSql,       /* SQL statement, UTF-8 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlcipher3_stmt **ppStmt,  /* OUT: Statement handle */
  const char **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLCIPHER_API int sqlcipher3_prepare16(
  sqlcipher3 *db,            /* Database handle */
  const void *zSql,       /* SQL statement, UTF-16 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlcipher3_stmt **ppStmt,  /* OUT: Statement handle */
  const void **pzTail     /* OUT: Pointer to unused portion of zSql */
);
SQLCIPHER_API int sqlcipher3_prepare16_v2(
  sqlcipher3 *db,            /* Database handle */
  const void *zSql,       /* SQL statement, UTF-16 encoded */
  int nByte,              /* Maximum length of zSql in bytes. */
  sqlcipher3_stmt **ppStmt,  /* OUT: Statement handle */
  const void **pzTail     /* OUT: Pointer to unused portion of zSql */
);

/*
** CAPI3REF: Retrieving Statement SQL
**
** ^This interface can be used to retrieve a saved copy of the original
** SQL text used to create a [prepared statement] if that statement was
** compiled using either [sqlcipher3_prepare_v2()] or [sqlcipher3_prepare16_v2()].
*/
SQLCIPHER_API const char *sqlcipher3_sql(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Determine If An SQL Statement Writes The Database
**
** ^The sqlcipher3_stmt_readonly(X) interface returns true (non-zero) if
** and only if the [prepared statement] X makes no direct changes to
** the content of the database file.
**
** Note that [application-defined SQL functions] or
** [virtual tables] might change the database indirectly as a side effect.  
** ^(For example, if an application defines a function "eval()" that 
** calls [sqlcipher3_exec()], then the following SQL statement would
** change the database file through side-effects:
**
** <blockquote><pre>
**    SELECT eval('DELETE FROM t1') FROM t2;
** </pre></blockquote>
**
** But because the [SELECT] statement does not change the database file
** directly, sqlcipher3_stmt_readonly() would still return true.)^
**
** ^Transaction control statements such as [BEGIN], [COMMIT], [ROLLBACK],
** [SAVEPOINT], and [RELEASE] cause sqlcipher3_stmt_readonly() to return true,
** since the statements themselves do not actually modify the database but
** rather they control the timing of when other statements modify the 
** database.  ^The [ATTACH] and [DETACH] statements also cause
** sqlcipher3_stmt_readonly() to return true since, while those statements
** change the configuration of a database connection, they do not make 
** changes to the content of the database files on disk.
*/
SQLCIPHER_API int sqlcipher3_stmt_readonly(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Dynamically Typed Value Object
** KEYWORDS: {protected sqlcipher3_value} {unprotected sqlcipher3_value}
**
** SQLite uses the sqlcipher3_value object to represent all values
** that can be stored in a database table. SQLite uses dynamic typing
** for the values it stores.  ^Values stored in sqlcipher3_value objects
** can be integers, floating point values, strings, BLOBs, or NULL.
**
** An sqlcipher3_value object may be either "protected" or "unprotected".
** Some interfaces require a protected sqlcipher3_value.  Other interfaces
** will accept either a protected or an unprotected sqlcipher3_value.
** Every interface that accepts sqlcipher3_value arguments specifies
** whether or not it requires a protected sqlcipher3_value.
**
** The terms "protected" and "unprotected" refer to whether or not
** a mutex is held.  An internal mutex is held for a protected
** sqlcipher3_value object but no mutex is held for an unprotected
** sqlcipher3_value object.  If SQLite is compiled to be single-threaded
** (with [SQLCIPHER_THREADSAFE=0] and with [sqlcipher3_threadsafe()] returning 0)
** or if SQLite is run in one of reduced mutex modes 
** [SQLCIPHER_CONFIG_SINGLETHREAD] or [SQLCIPHER_CONFIG_MULTITHREAD]
** then there is no distinction between protected and unprotected
** sqlcipher3_value objects and they can be used interchangeably.  However,
** for maximum code portability it is recommended that applications
** still make the distinction between protected and unprotected
** sqlcipher3_value objects even when not strictly required.
**
** ^The sqlcipher3_value objects that are passed as parameters into the
** implementation of [application-defined SQL functions] are protected.
** ^The sqlcipher3_value object returned by
** [sqlcipher3_column_value()] is unprotected.
** Unprotected sqlcipher3_value objects may only be used with
** [sqlcipher3_result_value()] and [sqlcipher3_bind_value()].
** The [sqlcipher3_value_blob | sqlcipher3_value_type()] family of
** interfaces require protected sqlcipher3_value objects.
*/
typedef struct Mem sqlcipher3_value;

/*
** CAPI3REF: SQL Function Context Object
**
** The context in which an SQL function executes is stored in an
** sqlcipher3_context object.  ^A pointer to an sqlcipher3_context object
** is always first parameter to [application-defined SQL functions].
** The application-defined SQL function implementation will pass this
** pointer through into calls to [sqlcipher3_result_int | sqlcipher3_result()],
** [sqlcipher3_aggregate_context()], [sqlcipher3_user_data()],
** [sqlcipher3_context_db_handle()], [sqlcipher3_get_auxdata()],
** and/or [sqlcipher3_set_auxdata()].
*/
typedef struct sqlcipher3_context sqlcipher3_context;

/*
** CAPI3REF: Binding Values To Prepared Statements
** KEYWORDS: {host parameter} {host parameters} {host parameter name}
** KEYWORDS: {SQL parameter} {SQL parameters} {parameter binding}
**
** ^(In the SQL statement text input to [sqlcipher3_prepare_v2()] and its variants,
** literals may be replaced by a [parameter] that matches one of following
** templates:
**
** <ul>
** <li>  ?
** <li>  ?NNN
** <li>  :VVV
** <li>  @VVV
** <li>  $VVV
** </ul>
**
** In the templates above, NNN represents an integer literal,
** and VVV represents an alphanumeric identifier.)^  ^The values of these
** parameters (also called "host parameter names" or "SQL parameters")
** can be set using the sqlcipher3_bind_*() routines defined here.
**
** ^The first argument to the sqlcipher3_bind_*() routines is always
** a pointer to the [sqlcipher3_stmt] object returned from
** [sqlcipher3_prepare_v2()] or its variants.
**
** ^The second argument is the index of the SQL parameter to be set.
** ^The leftmost SQL parameter has an index of 1.  ^When the same named
** SQL parameter is used more than once, second and subsequent
** occurrences have the same index as the first occurrence.
** ^The index for named parameters can be looked up using the
** [sqlcipher3_bind_parameter_index()] API if desired.  ^The index
** for "?NNN" parameters is the value of NNN.
** ^The NNN value must be between 1 and the [sqlcipher3_limit()]
** parameter [SQLCIPHER_LIMIT_VARIABLE_NUMBER] (default value: 999).
**
** ^The third argument is the value to bind to the parameter.
**
** ^(In those routines that have a fourth argument, its value is the
** number of bytes in the parameter.  To be clear: the value is the
** number of <u>bytes</u> in the value, not the number of characters.)^
** ^If the fourth parameter is negative, the length of the string is
** the number of bytes up to the first zero terminator.
** If a non-negative fourth parameter is provided to sqlcipher3_bind_text()
** or sqlcipher3_bind_text16() then that parameter must be the byte offset
** where the NUL terminator would occur assuming the string were NUL
** terminated.  If any NUL characters occur at byte offsets less than 
** the value of the fourth parameter then the resulting string value will
** contain embedded NULs.  The result of expressions involving strings
** with embedded NULs is undefined.
**
** ^The fifth argument to sqlcipher3_bind_blob(), sqlcipher3_bind_text(), and
** sqlcipher3_bind_text16() is a destructor used to dispose of the BLOB or
** string after SQLite has finished with it.  ^The destructor is called
** to dispose of the BLOB or string even if the call to sqlcipher3_bind_blob(),
** sqlcipher3_bind_text(), or sqlcipher3_bind_text16() fails.  
** ^If the fifth argument is
** the special value [SQLCIPHER_STATIC], then SQLite assumes that the
** information is in static, unmanaged space and does not need to be freed.
** ^If the fifth argument has the value [SQLCIPHER_TRANSIENT], then
** SQLite makes its own private copy of the data immediately, before
** the sqlcipher3_bind_*() routine returns.
**
** ^The sqlcipher3_bind_zeroblob() routine binds a BLOB of length N that
** is filled with zeroes.  ^A zeroblob uses a fixed amount of memory
** (just an integer to hold its size) while it is being processed.
** Zeroblobs are intended to serve as placeholders for BLOBs whose
** content is later written using
** [sqlcipher3_blob_open | incremental BLOB I/O] routines.
** ^A negative value for the zeroblob results in a zero-length BLOB.
**
** ^If any of the sqlcipher3_bind_*() routines are called with a NULL pointer
** for the [prepared statement] or with a prepared statement for which
** [sqlcipher3_step()] has been called more recently than [sqlcipher3_reset()],
** then the call will return [SQLCIPHER_MISUSE].  If any sqlcipher3_bind_()
** routine is passed a [prepared statement] that has been finalized, the
** result is undefined and probably harmful.
**
** ^Bindings are not cleared by the [sqlcipher3_reset()] routine.
** ^Unbound parameters are interpreted as NULL.
**
** ^The sqlcipher3_bind_* routines return [SQLCIPHER_OK] on success or an
** [error code] if anything goes wrong.
** ^[SQLCIPHER_RANGE] is returned if the parameter
** index is out of range.  ^[SQLCIPHER_NOMEM] is returned if malloc() fails.
**
** See also: [sqlcipher3_bind_parameter_count()],
** [sqlcipher3_bind_parameter_name()], and [sqlcipher3_bind_parameter_index()].
*/
SQLCIPHER_API int sqlcipher3_bind_blob(sqlcipher3_stmt*, int, const void*, int n, void(*)(void*));
SQLCIPHER_API int sqlcipher3_bind_double(sqlcipher3_stmt*, int, double);
SQLCIPHER_API int sqlcipher3_bind_int(sqlcipher3_stmt*, int, int);
SQLCIPHER_API int sqlcipher3_bind_int64(sqlcipher3_stmt*, int, sqlcipher3_int64);
SQLCIPHER_API int sqlcipher3_bind_null(sqlcipher3_stmt*, int);
SQLCIPHER_API int sqlcipher3_bind_text(sqlcipher3_stmt*, int, const char*, int n, void(*)(void*));
SQLCIPHER_API int sqlcipher3_bind_text16(sqlcipher3_stmt*, int, const void*, int, void(*)(void*));
SQLCIPHER_API int sqlcipher3_bind_value(sqlcipher3_stmt*, int, const sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_bind_zeroblob(sqlcipher3_stmt*, int, int n);

/*
** CAPI3REF: Number Of SQL Parameters
**
** ^This routine can be used to find the number of [SQL parameters]
** in a [prepared statement].  SQL parameters are tokens of the
** form "?", "?NNN", ":AAA", "$AAA", or "@AAA" that serve as
** placeholders for values that are [sqlcipher3_bind_blob | bound]
** to the parameters at a later time.
**
** ^(This routine actually returns the index of the largest (rightmost)
** parameter. For all forms except ?NNN, this will correspond to the
** number of unique parameters.  If parameters of the ?NNN form are used,
** there may be gaps in the list.)^
**
** See also: [sqlcipher3_bind_blob|sqlcipher3_bind()],
** [sqlcipher3_bind_parameter_name()], and
** [sqlcipher3_bind_parameter_index()].
*/
SQLCIPHER_API int sqlcipher3_bind_parameter_count(sqlcipher3_stmt*);

/*
** CAPI3REF: Name Of A Host Parameter
**
** ^The sqlcipher3_bind_parameter_name(P,N) interface returns
** the name of the N-th [SQL parameter] in the [prepared statement] P.
** ^(SQL parameters of the form "?NNN" or ":AAA" or "@AAA" or "$AAA"
** have a name which is the string "?NNN" or ":AAA" or "@AAA" or "$AAA"
** respectively.
** In other words, the initial ":" or "$" or "@" or "?"
** is included as part of the name.)^
** ^Parameters of the form "?" without a following integer have no name
** and are referred to as "nameless" or "anonymous parameters".
**
** ^The first host parameter has an index of 1, not 0.
**
** ^If the value N is out of range or if the N-th parameter is
** nameless, then NULL is returned.  ^The returned string is
** always in UTF-8 encoding even if the named parameter was
** originally specified as UTF-16 in [sqlcipher3_prepare16()] or
** [sqlcipher3_prepare16_v2()].
**
** See also: [sqlcipher3_bind_blob|sqlcipher3_bind()],
** [sqlcipher3_bind_parameter_count()], and
** [sqlcipher3_bind_parameter_index()].
*/
SQLCIPHER_API const char *sqlcipher3_bind_parameter_name(sqlcipher3_stmt*, int);

/*
** CAPI3REF: Index Of A Parameter With A Given Name
**
** ^Return the index of an SQL parameter given its name.  ^The
** index value returned is suitable for use as the second
** parameter to [sqlcipher3_bind_blob|sqlcipher3_bind()].  ^A zero
** is returned if no matching parameter is found.  ^The parameter
** name must be given in UTF-8 even if the original statement
** was prepared from UTF-16 text using [sqlcipher3_prepare16_v2()].
**
** See also: [sqlcipher3_bind_blob|sqlcipher3_bind()],
** [sqlcipher3_bind_parameter_count()], and
** [sqlcipher3_bind_parameter_index()].
*/
SQLCIPHER_API int sqlcipher3_bind_parameter_index(sqlcipher3_stmt*, const char *zName);

/*
** CAPI3REF: Reset All Bindings On A Prepared Statement
**
** ^Contrary to the intuition of many, [sqlcipher3_reset()] does not reset
** the [sqlcipher3_bind_blob | bindings] on a [prepared statement].
** ^Use this routine to reset all host parameters to NULL.
*/
SQLCIPHER_API int sqlcipher3_clear_bindings(sqlcipher3_stmt*);

/*
** CAPI3REF: Number Of Columns In A Result Set
**
** ^Return the number of columns in the result set returned by the
** [prepared statement]. ^This routine returns 0 if pStmt is an SQL
** statement that does not return data (for example an [UPDATE]).
**
** See also: [sqlcipher3_data_count()]
*/
SQLCIPHER_API int sqlcipher3_column_count(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Column Names In A Result Set
**
** ^These routines return the name assigned to a particular column
** in the result set of a [SELECT] statement.  ^The sqlcipher3_column_name()
** interface returns a pointer to a zero-terminated UTF-8 string
** and sqlcipher3_column_name16() returns a pointer to a zero-terminated
** UTF-16 string.  ^The first parameter is the [prepared statement]
** that implements the [SELECT] statement. ^The second parameter is the
** column number.  ^The leftmost column is number 0.
**
** ^The returned string pointer is valid until either the [prepared statement]
** is destroyed by [sqlcipher3_finalize()] or until the statement is automatically
** reprepared by the first call to [sqlcipher3_step()] for a particular run
** or until the next call to
** sqlcipher3_column_name() or sqlcipher3_column_name16() on the same column.
**
** ^If sqlcipher3_malloc() fails during the processing of either routine
** (for example during a conversion from UTF-8 to UTF-16) then a
** NULL pointer is returned.
**
** ^The name of a result column is the value of the "AS" clause for
** that column, if there is an AS clause.  If there is no AS clause
** then the name of the column is unspecified and may change from
** one release of SQLite to the next.
*/
SQLCIPHER_API const char *sqlcipher3_column_name(sqlcipher3_stmt*, int N);
SQLCIPHER_API const void *sqlcipher3_column_name16(sqlcipher3_stmt*, int N);

/*
** CAPI3REF: Source Of Data In A Query Result
**
** ^These routines provide a means to determine the database, table, and
** table column that is the origin of a particular result column in
** [SELECT] statement.
** ^The name of the database or table or column can be returned as
** either a UTF-8 or UTF-16 string.  ^The _database_ routines return
** the database name, the _table_ routines return the table name, and
** the origin_ routines return the column name.
** ^The returned string is valid until the [prepared statement] is destroyed
** using [sqlcipher3_finalize()] or until the statement is automatically
** reprepared by the first call to [sqlcipher3_step()] for a particular run
** or until the same information is requested
** again in a different encoding.
**
** ^The names returned are the original un-aliased names of the
** database, table, and column.
**
** ^The first argument to these interfaces is a [prepared statement].
** ^These functions return information about the Nth result column returned by
** the statement, where N is the second function argument.
** ^The left-most column is column 0 for these routines.
**
** ^If the Nth column returned by the statement is an expression or
** subquery and is not a column value, then all of these functions return
** NULL.  ^These routine might also return NULL if a memory allocation error
** occurs.  ^Otherwise, they return the name of the attached database, table,
** or column that query result column was extracted from.
**
** ^As with all other SQLite APIs, those whose names end with "16" return
** UTF-16 encoded strings and the other functions return UTF-8.
**
** ^These APIs are only available if the library was compiled with the
** [SQLCIPHER_ENABLE_COLUMN_METADATA] C-preprocessor symbol.
**
** If two or more threads call one or more of these routines against the same
** prepared statement and column at the same time then the results are
** undefined.
**
** If two or more threads call one or more
** [sqlcipher3_column_database_name | column metadata interfaces]
** for the same [prepared statement] and result column
** at the same time then the results are undefined.
*/
SQLCIPHER_API const char *sqlcipher3_column_database_name(sqlcipher3_stmt*,int);
SQLCIPHER_API const void *sqlcipher3_column_database_name16(sqlcipher3_stmt*,int);
SQLCIPHER_API const char *sqlcipher3_column_table_name(sqlcipher3_stmt*,int);
SQLCIPHER_API const void *sqlcipher3_column_table_name16(sqlcipher3_stmt*,int);
SQLCIPHER_API const char *sqlcipher3_column_origin_name(sqlcipher3_stmt*,int);
SQLCIPHER_API const void *sqlcipher3_column_origin_name16(sqlcipher3_stmt*,int);

/*
** CAPI3REF: Declared Datatype Of A Query Result
**
** ^(The first parameter is a [prepared statement].
** If this statement is a [SELECT] statement and the Nth column of the
** returned result set of that [SELECT] is a table column (not an
** expression or subquery) then the declared type of the table
** column is returned.)^  ^If the Nth column of the result set is an
** expression or subquery, then a NULL pointer is returned.
** ^The returned string is always UTF-8 encoded.
**
** ^(For example, given the database schema:
**
** CREATE TABLE t1(c1 VARIANT);
**
** and the following statement to be compiled:
**
** SELECT c1 + 1, c1 FROM t1;
**
** this routine would return the string "VARIANT" for the second result
** column (i==1), and a NULL pointer for the first result column (i==0).)^
**
** ^SQLite uses dynamic run-time typing.  ^So just because a column
** is declared to contain a particular type does not mean that the
** data stored in that column is of the declared type.  SQLite is
** strongly typed, but the typing is dynamic not static.  ^Type
** is associated with individual values, not with the containers
** used to hold those values.
*/
SQLCIPHER_API const char *sqlcipher3_column_decltype(sqlcipher3_stmt*,int);
SQLCIPHER_API const void *sqlcipher3_column_decltype16(sqlcipher3_stmt*,int);

/*
** CAPI3REF: Evaluate An SQL Statement
**
** After a [prepared statement] has been prepared using either
** [sqlcipher3_prepare_v2()] or [sqlcipher3_prepare16_v2()] or one of the legacy
** interfaces [sqlcipher3_prepare()] or [sqlcipher3_prepare16()], this function
** must be called one or more times to evaluate the statement.
**
** The details of the behavior of the sqlcipher3_step() interface depend
** on whether the statement was prepared using the newer "v2" interface
** [sqlcipher3_prepare_v2()] and [sqlcipher3_prepare16_v2()] or the older legacy
** interface [sqlcipher3_prepare()] and [sqlcipher3_prepare16()].  The use of the
** new "v2" interface is recommended for new applications but the legacy
** interface will continue to be supported.
**
** ^In the legacy interface, the return value will be either [SQLCIPHER_BUSY],
** [SQLCIPHER_DONE], [SQLCIPHER_ROW], [SQLCIPHER_ERROR], or [SQLCIPHER_MISUSE].
** ^With the "v2" interface, any of the other [result codes] or
** [extended result codes] might be returned as well.
**
** ^[SQLCIPHER_BUSY] means that the database engine was unable to acquire the
** database locks it needs to do its job.  ^If the statement is a [COMMIT]
** or occurs outside of an explicit transaction, then you can retry the
** statement.  If the statement is not a [COMMIT] and occurs within an
** explicit transaction then you should rollback the transaction before
** continuing.
**
** ^[SQLCIPHER_DONE] means that the statement has finished executing
** successfully.  sqlcipher3_step() should not be called again on this virtual
** machine without first calling [sqlcipher3_reset()] to reset the virtual
** machine back to its initial state.
**
** ^If the SQL statement being executed returns any data, then [SQLCIPHER_ROW]
** is returned each time a new row of data is ready for processing by the
** caller. The values may be accessed using the [column access functions].
** sqlcipher3_step() is called again to retrieve the next row of data.
**
** ^[SQLCIPHER_ERROR] means that a run-time error (such as a constraint
** violation) has occurred.  sqlcipher3_step() should not be called again on
** the VM. More information may be found by calling [sqlcipher3_errmsg()].
** ^With the legacy interface, a more specific error code (for example,
** [SQLCIPHER_INTERRUPT], [SQLCIPHER_SCHEMA], [SQLCIPHER_CORRUPT], and so forth)
** can be obtained by calling [sqlcipher3_reset()] on the
** [prepared statement].  ^In the "v2" interface,
** the more specific error code is returned directly by sqlcipher3_step().
**
** [SQLCIPHER_MISUSE] means that the this routine was called inappropriately.
** Perhaps it was called on a [prepared statement] that has
** already been [sqlcipher3_finalize | finalized] or on one that had
** previously returned [SQLCIPHER_ERROR] or [SQLCIPHER_DONE].  Or it could
** be the case that the same database connection is being used by two or
** more threads at the same moment in time.
**
** For all versions of SQLite up to and including 3.6.23.1, a call to
** [sqlcipher3_reset()] was required after sqlcipher3_step() returned anything
** other than [SQLCIPHER_ROW] before any subsequent invocation of
** sqlcipher3_step().  Failure to reset the prepared statement using 
** [sqlcipher3_reset()] would result in an [SQLCIPHER_MISUSE] return from
** sqlcipher3_step().  But after version 3.6.23.1, sqlcipher3_step() began
** calling [sqlcipher3_reset()] automatically in this circumstance rather
** than returning [SQLCIPHER_MISUSE].  This is not considered a compatibility
** break because any application that ever receives an SQLCIPHER_MISUSE error
** is broken by definition.  The [SQLCIPHER_OMIT_AUTORESET] compile-time option
** can be used to restore the legacy behavior.
**
** <b>Goofy Interface Alert:</b> In the legacy interface, the sqlcipher3_step()
** API always returns a generic error code, [SQLCIPHER_ERROR], following any
** error other than [SQLCIPHER_BUSY] and [SQLCIPHER_MISUSE].  You must call
** [sqlcipher3_reset()] or [sqlcipher3_finalize()] in order to find one of the
** specific [error codes] that better describes the error.
** We admit that this is a goofy design.  The problem has been fixed
** with the "v2" interface.  If you prepare all of your SQL statements
** using either [sqlcipher3_prepare_v2()] or [sqlcipher3_prepare16_v2()] instead
** of the legacy [sqlcipher3_prepare()] and [sqlcipher3_prepare16()] interfaces,
** then the more specific [error codes] are returned directly
** by sqlcipher3_step().  The use of the "v2" interface is recommended.
*/
SQLCIPHER_API int sqlcipher3_step(sqlcipher3_stmt*);

/*
** CAPI3REF: Number of columns in a result set
**
** ^The sqlcipher3_data_count(P) interface returns the number of columns in the
** current row of the result set of [prepared statement] P.
** ^If prepared statement P does not have results ready to return
** (via calls to the [sqlcipher3_column_int | sqlcipher3_column_*()] of
** interfaces) then sqlcipher3_data_count(P) returns 0.
** ^The sqlcipher3_data_count(P) routine also returns 0 if P is a NULL pointer.
** ^The sqlcipher3_data_count(P) routine returns 0 if the previous call to
** [sqlcipher3_step](P) returned [SQLCIPHER_DONE].  ^The sqlcipher3_data_count(P)
** will return non-zero if previous call to [sqlcipher3_step](P) returned
** [SQLCIPHER_ROW], except in the case of the [PRAGMA incremental_vacuum]
** where it always returns zero since each step of that multi-step
** pragma returns 0 columns of data.
**
** See also: [sqlcipher3_column_count()]
*/
SQLCIPHER_API int sqlcipher3_data_count(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Fundamental Datatypes
** KEYWORDS: SQLCIPHER_TEXT
**
** ^(Every value in SQLite has one of five fundamental datatypes:
**
** <ul>
** <li> 64-bit signed integer
** <li> 64-bit IEEE floating point number
** <li> string
** <li> BLOB
** <li> NULL
** </ul>)^
**
** These constants are codes for each of those types.
**
** Note that the SQLCIPHER_TEXT constant was also used in SQLite version 2
** for a completely different meaning.  Software that links against both
** SQLite version 2 and SQLite version 3 should use SQLCIPHER3_TEXT, not
** SQLCIPHER_TEXT.
*/
#define SQLCIPHER_INTEGER  1
#define SQLCIPHER_FLOAT    2
#define SQLCIPHER_BLOB     4
#define SQLCIPHER_NULL     5
#ifdef SQLCIPHER_TEXT
# undef SQLCIPHER_TEXT
#else
# define SQLCIPHER_TEXT     3
#endif
#define SQLCIPHER3_TEXT     3

/*
** CAPI3REF: Result Values From A Query
** KEYWORDS: {column access functions}
**
** These routines form the "result set" interface.
**
** ^These routines return information about a single column of the current
** result row of a query.  ^In every case the first argument is a pointer
** to the [prepared statement] that is being evaluated (the [sqlcipher3_stmt*]
** that was returned from [sqlcipher3_prepare_v2()] or one of its variants)
** and the second argument is the index of the column for which information
** should be returned. ^The leftmost column of the result set has the index 0.
** ^The number of columns in the result can be determined using
** [sqlcipher3_column_count()].
**
** If the SQL statement does not currently point to a valid row, or if the
** column index is out of range, the result is undefined.
** These routines may only be called when the most recent call to
** [sqlcipher3_step()] has returned [SQLCIPHER_ROW] and neither
** [sqlcipher3_reset()] nor [sqlcipher3_finalize()] have been called subsequently.
** If any of these routines are called after [sqlcipher3_reset()] or
** [sqlcipher3_finalize()] or after [sqlcipher3_step()] has returned
** something other than [SQLCIPHER_ROW], the results are undefined.
** If [sqlcipher3_step()] or [sqlcipher3_reset()] or [sqlcipher3_finalize()]
** are called from a different thread while any of these routines
** are pending, then the results are undefined.
**
** ^The sqlcipher3_column_type() routine returns the
** [SQLCIPHER_INTEGER | datatype code] for the initial data type
** of the result column.  ^The returned value is one of [SQLCIPHER_INTEGER],
** [SQLCIPHER_FLOAT], [SQLCIPHER_TEXT], [SQLCIPHER_BLOB], or [SQLCIPHER_NULL].  The value
** returned by sqlcipher3_column_type() is only meaningful if no type
** conversions have occurred as described below.  After a type conversion,
** the value returned by sqlcipher3_column_type() is undefined.  Future
** versions of SQLite may change the behavior of sqlcipher3_column_type()
** following a type conversion.
**
** ^If the result is a BLOB or UTF-8 string then the sqlcipher3_column_bytes()
** routine returns the number of bytes in that BLOB or string.
** ^If the result is a UTF-16 string, then sqlcipher3_column_bytes() converts
** the string to UTF-8 and then returns the number of bytes.
** ^If the result is a numeric value then sqlcipher3_column_bytes() uses
** [sqlcipher3_snprintf()] to convert that value to a UTF-8 string and returns
** the number of bytes in that string.
** ^If the result is NULL, then sqlcipher3_column_bytes() returns zero.
**
** ^If the result is a BLOB or UTF-16 string then the sqlcipher3_column_bytes16()
** routine returns the number of bytes in that BLOB or string.
** ^If the result is a UTF-8 string, then sqlcipher3_column_bytes16() converts
** the string to UTF-16 and then returns the number of bytes.
** ^If the result is a numeric value then sqlcipher3_column_bytes16() uses
** [sqlcipher3_snprintf()] to convert that value to a UTF-16 string and returns
** the number of bytes in that string.
** ^If the result is NULL, then sqlcipher3_column_bytes16() returns zero.
**
** ^The values returned by [sqlcipher3_column_bytes()] and 
** [sqlcipher3_column_bytes16()] do not include the zero terminators at the end
** of the string.  ^For clarity: the values returned by
** [sqlcipher3_column_bytes()] and [sqlcipher3_column_bytes16()] are the number of
** bytes in the string, not the number of characters.
**
** ^Strings returned by sqlcipher3_column_text() and sqlcipher3_column_text16(),
** even empty strings, are always zero terminated.  ^The return
** value from sqlcipher3_column_blob() for a zero-length BLOB is a NULL pointer.
**
** ^The object returned by [sqlcipher3_column_value()] is an
** [unprotected sqlcipher3_value] object.  An unprotected sqlcipher3_value object
** may only be used with [sqlcipher3_bind_value()] and [sqlcipher3_result_value()].
** If the [unprotected sqlcipher3_value] object returned by
** [sqlcipher3_column_value()] is used in any other way, including calls
** to routines like [sqlcipher3_value_int()], [sqlcipher3_value_text()],
** or [sqlcipher3_value_bytes()], then the behavior is undefined.
**
** These routines attempt to convert the value where appropriate.  ^For
** example, if the internal representation is FLOAT and a text result
** is requested, [sqlcipher3_snprintf()] is used internally to perform the
** conversion automatically.  ^(The following table details the conversions
** that are applied:
**
** <blockquote>
** <table border="1">
** <tr><th> Internal<br>Type <th> Requested<br>Type <th>  Conversion
**
** <tr><td>  NULL    <td> INTEGER   <td> Result is 0
** <tr><td>  NULL    <td>  FLOAT    <td> Result is 0.0
** <tr><td>  NULL    <td>   TEXT    <td> Result is NULL pointer
** <tr><td>  NULL    <td>   BLOB    <td> Result is NULL pointer
** <tr><td> INTEGER  <td>  FLOAT    <td> Convert from integer to float
** <tr><td> INTEGER  <td>   TEXT    <td> ASCII rendering of the integer
** <tr><td> INTEGER  <td>   BLOB    <td> Same as INTEGER->TEXT
** <tr><td>  FLOAT   <td> INTEGER   <td> Convert from float to integer
** <tr><td>  FLOAT   <td>   TEXT    <td> ASCII rendering of the float
** <tr><td>  FLOAT   <td>   BLOB    <td> Same as FLOAT->TEXT
** <tr><td>  TEXT    <td> INTEGER   <td> Use atoi()
** <tr><td>  TEXT    <td>  FLOAT    <td> Use atof()
** <tr><td>  TEXT    <td>   BLOB    <td> No change
** <tr><td>  BLOB    <td> INTEGER   <td> Convert to TEXT then use atoi()
** <tr><td>  BLOB    <td>  FLOAT    <td> Convert to TEXT then use atof()
** <tr><td>  BLOB    <td>   TEXT    <td> Add a zero terminator if needed
** </table>
** </blockquote>)^
**
** The table above makes reference to standard C library functions atoi()
** and atof().  SQLite does not really use these functions.  It has its
** own equivalent internal routines.  The atoi() and atof() names are
** used in the table for brevity and because they are familiar to most
** C programmers.
**
** Note that when type conversions occur, pointers returned by prior
** calls to sqlcipher3_column_blob(), sqlcipher3_column_text(), and/or
** sqlcipher3_column_text16() may be invalidated.
** Type conversions and pointer invalidations might occur
** in the following cases:
**
** <ul>
** <li> The initial content is a BLOB and sqlcipher3_column_text() or
**      sqlcipher3_column_text16() is called.  A zero-terminator might
**      need to be added to the string.</li>
** <li> The initial content is UTF-8 text and sqlcipher3_column_bytes16() or
**      sqlcipher3_column_text16() is called.  The content must be converted
**      to UTF-16.</li>
** <li> The initial content is UTF-16 text and sqlcipher3_column_bytes() or
**      sqlcipher3_column_text() is called.  The content must be converted
**      to UTF-8.</li>
** </ul>
**
** ^Conversions between UTF-16be and UTF-16le are always done in place and do
** not invalidate a prior pointer, though of course the content of the buffer
** that the prior pointer references will have been modified.  Other kinds
** of conversion are done in place when it is possible, but sometimes they
** are not possible and in those cases prior pointers are invalidated.
**
** The safest and easiest to remember policy is to invoke these routines
** in one of the following ways:
**
** <ul>
**  <li>sqlcipher3_column_text() followed by sqlcipher3_column_bytes()</li>
**  <li>sqlcipher3_column_blob() followed by sqlcipher3_column_bytes()</li>
**  <li>sqlcipher3_column_text16() followed by sqlcipher3_column_bytes16()</li>
** </ul>
**
** In other words, you should call sqlcipher3_column_text(),
** sqlcipher3_column_blob(), or sqlcipher3_column_text16() first to force the result
** into the desired format, then invoke sqlcipher3_column_bytes() or
** sqlcipher3_column_bytes16() to find the size of the result.  Do not mix calls
** to sqlcipher3_column_text() or sqlcipher3_column_blob() with calls to
** sqlcipher3_column_bytes16(), and do not mix calls to sqlcipher3_column_text16()
** with calls to sqlcipher3_column_bytes().
**
** ^The pointers returned are valid until a type conversion occurs as
** described above, or until [sqlcipher3_step()] or [sqlcipher3_reset()] or
** [sqlcipher3_finalize()] is called.  ^The memory space used to hold strings
** and BLOBs is freed automatically.  Do <b>not</b> pass the pointers returned
** [sqlcipher3_column_blob()], [sqlcipher3_column_text()], etc. into
** [sqlcipher3_free()].
**
** ^(If a memory allocation error occurs during the evaluation of any
** of these routines, a default value is returned.  The default value
** is either the integer 0, the floating point number 0.0, or a NULL
** pointer.  Subsequent calls to [sqlcipher3_errcode()] will return
** [SQLCIPHER_NOMEM].)^
*/
SQLCIPHER_API const void *sqlcipher3_column_blob(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API int sqlcipher3_column_bytes(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API int sqlcipher3_column_bytes16(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API double sqlcipher3_column_double(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API int sqlcipher3_column_int(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_column_int64(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API const unsigned char *sqlcipher3_column_text(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API const void *sqlcipher3_column_text16(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API int sqlcipher3_column_type(sqlcipher3_stmt*, int iCol);
SQLCIPHER_API sqlcipher3_value *sqlcipher3_column_value(sqlcipher3_stmt*, int iCol);

/*
** CAPI3REF: Destroy A Prepared Statement Object
**
** ^The sqlcipher3_finalize() function is called to delete a [prepared statement].
** ^If the most recent evaluation of the statement encountered no errors
** or if the statement is never been evaluated, then sqlcipher3_finalize() returns
** SQLCIPHER_OK.  ^If the most recent evaluation of statement S failed, then
** sqlcipher3_finalize(S) returns the appropriate [error code] or
** [extended error code].
**
** ^The sqlcipher3_finalize(S) routine can be called at any point during
** the life cycle of [prepared statement] S:
** before statement S is ever evaluated, after
** one or more calls to [sqlcipher3_reset()], or after any call
** to [sqlcipher3_step()] regardless of whether or not the statement has
** completed execution.
**
** ^Invoking sqlcipher3_finalize() on a NULL pointer is a harmless no-op.
**
** The application must finalize every [prepared statement] in order to avoid
** resource leaks.  It is a grievous error for the application to try to use
** a prepared statement after it has been finalized.  Any use of a prepared
** statement after it has been finalized can result in undefined and
** undesirable behavior such as segfaults and heap corruption.
*/
SQLCIPHER_API int sqlcipher3_finalize(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Reset A Prepared Statement Object
**
** The sqlcipher3_reset() function is called to reset a [prepared statement]
** object back to its initial state, ready to be re-executed.
** ^Any SQL statement variables that had values bound to them using
** the [sqlcipher3_bind_blob | sqlcipher3_bind_*() API] retain their values.
** Use [sqlcipher3_clear_bindings()] to reset the bindings.
**
** ^The [sqlcipher3_reset(S)] interface resets the [prepared statement] S
** back to the beginning of its program.
**
** ^If the most recent call to [sqlcipher3_step(S)] for the
** [prepared statement] S returned [SQLCIPHER_ROW] or [SQLCIPHER_DONE],
** or if [sqlcipher3_step(S)] has never before been called on S,
** then [sqlcipher3_reset(S)] returns [SQLCIPHER_OK].
**
** ^If the most recent call to [sqlcipher3_step(S)] for the
** [prepared statement] S indicated an error, then
** [sqlcipher3_reset(S)] returns an appropriate [error code].
**
** ^The [sqlcipher3_reset(S)] interface does not change the values
** of any [sqlcipher3_bind_blob|bindings] on the [prepared statement] S.
*/
SQLCIPHER_API int sqlcipher3_reset(sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Create Or Redefine SQL Functions
** KEYWORDS: {function creation routines}
** KEYWORDS: {application-defined SQL function}
** KEYWORDS: {application-defined SQL functions}
**
** ^These functions (collectively known as "function creation routines")
** are used to add SQL functions or aggregates or to redefine the behavior
** of existing SQL functions or aggregates.  The only differences between
** these routines are the text encoding expected for
** the second parameter (the name of the function being created)
** and the presence or absence of a destructor callback for
** the application data pointer.
**
** ^The first parameter is the [database connection] to which the SQL
** function is to be added.  ^If an application uses more than one database
** connection then application-defined SQL functions must be added
** to each database connection separately.
**
** ^The second parameter is the name of the SQL function to be created or
** redefined.  ^The length of the name is limited to 255 bytes in a UTF-8
** representation, exclusive of the zero-terminator.  ^Note that the name
** length limit is in UTF-8 bytes, not characters nor UTF-16 bytes.  
** ^Any attempt to create a function with a longer name
** will result in [SQLCIPHER_MISUSE] being returned.
**
** ^The third parameter (nArg)
** is the number of arguments that the SQL function or
** aggregate takes. ^If this parameter is -1, then the SQL function or
** aggregate may take any number of arguments between 0 and the limit
** set by [sqlcipher3_limit]([SQLCIPHER_LIMIT_FUNCTION_ARG]).  If the third
** parameter is less than -1 or greater than 127 then the behavior is
** undefined.
**
** ^The fourth parameter, eTextRep, specifies what
** [SQLCIPHER_UTF8 | text encoding] this SQL function prefers for
** its parameters.  Every SQL function implementation must be able to work
** with UTF-8, UTF-16le, or UTF-16be.  But some implementations may be
** more efficient with one encoding than another.  ^An application may
** invoke sqlcipher3_create_function() or sqlcipher3_create_function16() multiple
** times with the same function but with different values of eTextRep.
** ^When multiple implementations of the same function are available, SQLite
** will pick the one that involves the least amount of data conversion.
** If there is only a single implementation which does not care what text
** encoding is used, then the fourth argument should be [SQLCIPHER_ANY].
**
** ^(The fifth parameter is an arbitrary pointer.  The implementation of the
** function can gain access to this pointer using [sqlcipher3_user_data()].)^
**
** ^The sixth, seventh and eighth parameters, xFunc, xStep and xFinal, are
** pointers to C-language functions that implement the SQL function or
** aggregate. ^A scalar SQL function requires an implementation of the xFunc
** callback only; NULL pointers must be passed as the xStep and xFinal
** parameters. ^An aggregate SQL function requires an implementation of xStep
** and xFinal and NULL pointer must be passed for xFunc. ^To delete an existing
** SQL function or aggregate, pass NULL pointers for all three function
** callbacks.
**
** ^(If the ninth parameter to sqlcipher3_create_function_v2() is not NULL,
** then it is destructor for the application data pointer. 
** The destructor is invoked when the function is deleted, either by being
** overloaded or when the database connection closes.)^
** ^The destructor is also invoked if the call to
** sqlcipher3_create_function_v2() fails.
** ^When the destructor callback of the tenth parameter is invoked, it
** is passed a single argument which is a copy of the application data 
** pointer which was the fifth parameter to sqlcipher3_create_function_v2().
**
** ^It is permitted to register multiple implementations of the same
** functions with the same name but with either differing numbers of
** arguments or differing preferred text encodings.  ^SQLite will use
** the implementation that most closely matches the way in which the
** SQL function is used.  ^A function implementation with a non-negative
** nArg parameter is a better match than a function implementation with
** a negative nArg.  ^A function where the preferred text encoding
** matches the database encoding is a better
** match than a function where the encoding is different.  
** ^A function where the encoding difference is between UTF16le and UTF16be
** is a closer match than a function where the encoding difference is
** between UTF8 and UTF16.
**
** ^Built-in functions may be overloaded by new application-defined functions.
**
** ^An application-defined function is permitted to call other
** SQLite interfaces.  However, such calls must not
** close the database connection nor finalize or reset the prepared
** statement in which the function is running.
*/
SQLCIPHER_API int sqlcipher3_create_function(
  sqlcipher3 *db,
  const char *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xStep)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xFinal)(sqlcipher3_context*)
);
SQLCIPHER_API int sqlcipher3_create_function16(
  sqlcipher3 *db,
  const void *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xStep)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xFinal)(sqlcipher3_context*)
);
SQLCIPHER_API int sqlcipher3_create_function_v2(
  sqlcipher3 *db,
  const char *zFunctionName,
  int nArg,
  int eTextRep,
  void *pApp,
  void (*xFunc)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xStep)(sqlcipher3_context*,int,sqlcipher3_value**),
  void (*xFinal)(sqlcipher3_context*),
  void(*xDestroy)(void*)
);

/*
** CAPI3REF: Text Encodings
**
** These constant define integer codes that represent the various
** text encodings supported by SQLite.
*/
#define SQLCIPHER_UTF8           1
#define SQLCIPHER_UTF16LE        2
#define SQLCIPHER_UTF16BE        3
#define SQLCIPHER_UTF16          4    /* Use native byte order */
#define SQLCIPHER_ANY            5    /* sqlcipher3_create_function only */
#define SQLCIPHER_UTF16_ALIGNED  8    /* sqlcipher3_create_collation only */

/*
** CAPI3REF: Deprecated Functions
** DEPRECATED
**
** These functions are [deprecated].  In order to maintain
** backwards compatibility with older code, these functions continue 
** to be supported.  However, new applications should avoid
** the use of these functions.  To help encourage people to avoid
** using these functions, we are not going to tell you what they do.
*/
#ifndef SQLCIPHER_OMIT_DEPRECATED
SQLCIPHER_API SQLCIPHER_DEPRECATED int sqlcipher3_aggregate_count(sqlcipher3_context*);
SQLCIPHER_API SQLCIPHER_DEPRECATED int sqlcipher3_expired(sqlcipher3_stmt*);
SQLCIPHER_API SQLCIPHER_DEPRECATED int sqlcipher3_transfer_bindings(sqlcipher3_stmt*, sqlcipher3_stmt*);
SQLCIPHER_API SQLCIPHER_DEPRECATED int sqlcipher3_global_recover(void);
SQLCIPHER_API SQLCIPHER_DEPRECATED void sqlcipher3_thread_cleanup(void);
SQLCIPHER_API SQLCIPHER_DEPRECATED int sqlcipher3_memory_alarm(void(*)(void*,sqlcipher3_int64,int),void*,sqlcipher3_int64);
#endif

/*
** CAPI3REF: Obtaining SQL Function Parameter Values
**
** The C-language implementation of SQL functions and aggregates uses
** this set of interface routines to access the parameter values on
** the function or aggregate.
**
** The xFunc (for scalar functions) or xStep (for aggregates) parameters
** to [sqlcipher3_create_function()] and [sqlcipher3_create_function16()]
** define callbacks that implement the SQL functions and aggregates.
** The 3rd parameter to these callbacks is an array of pointers to
** [protected sqlcipher3_value] objects.  There is one [sqlcipher3_value] object for
** each parameter to the SQL function.  These routines are used to
** extract values from the [sqlcipher3_value] objects.
**
** These routines work only with [protected sqlcipher3_value] objects.
** Any attempt to use these routines on an [unprotected sqlcipher3_value]
** object results in undefined behavior.
**
** ^These routines work just like the corresponding [column access functions]
** except that  these routines take a single [protected sqlcipher3_value] object
** pointer instead of a [sqlcipher3_stmt*] pointer and an integer column number.
**
** ^The sqlcipher3_value_text16() interface extracts a UTF-16 string
** in the native byte-order of the host machine.  ^The
** sqlcipher3_value_text16be() and sqlcipher3_value_text16le() interfaces
** extract UTF-16 strings as big-endian and little-endian respectively.
**
** ^(The sqlcipher3_value_numeric_type() interface attempts to apply
** numeric affinity to the value.  This means that an attempt is
** made to convert the value to an integer or floating point.  If
** such a conversion is possible without loss of information (in other
** words, if the value is a string that looks like a number)
** then the conversion is performed.  Otherwise no conversion occurs.
** The [SQLCIPHER_INTEGER | datatype] after conversion is returned.)^
**
** Please pay particular attention to the fact that the pointer returned
** from [sqlcipher3_value_blob()], [sqlcipher3_value_text()], or
** [sqlcipher3_value_text16()] can be invalidated by a subsequent call to
** [sqlcipher3_value_bytes()], [sqlcipher3_value_bytes16()], [sqlcipher3_value_text()],
** or [sqlcipher3_value_text16()].
**
** These routines must be called from the same thread as
** the SQL function that supplied the [sqlcipher3_value*] parameters.
*/
SQLCIPHER_API const void *sqlcipher3_value_blob(sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_value_bytes(sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_value_bytes16(sqlcipher3_value*);
SQLCIPHER_API double sqlcipher3_value_double(sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_value_int(sqlcipher3_value*);
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_value_int64(sqlcipher3_value*);
SQLCIPHER_API const unsigned char *sqlcipher3_value_text(sqlcipher3_value*);
SQLCIPHER_API const void *sqlcipher3_value_text16(sqlcipher3_value*);
SQLCIPHER_API const void *sqlcipher3_value_text16le(sqlcipher3_value*);
SQLCIPHER_API const void *sqlcipher3_value_text16be(sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_value_type(sqlcipher3_value*);
SQLCIPHER_API int sqlcipher3_value_numeric_type(sqlcipher3_value*);

/*
** CAPI3REF: Obtain Aggregate Function Context
**
** Implementations of aggregate SQL functions use this
** routine to allocate memory for storing their state.
**
** ^The first time the sqlcipher3_aggregate_context(C,N) routine is called 
** for a particular aggregate function, SQLite
** allocates N of memory, zeroes out that memory, and returns a pointer
** to the new memory. ^On second and subsequent calls to
** sqlcipher3_aggregate_context() for the same aggregate function instance,
** the same buffer is returned.  Sqlite3_aggregate_context() is normally
** called once for each invocation of the xStep callback and then one
** last time when the xFinal callback is invoked.  ^(When no rows match
** an aggregate query, the xStep() callback of the aggregate function
** implementation is never called and xFinal() is called exactly once.
** In those cases, sqlcipher3_aggregate_context() might be called for the
** first time from within xFinal().)^
**
** ^The sqlcipher3_aggregate_context(C,N) routine returns a NULL pointer if N is
** less than or equal to zero or if a memory allocate error occurs.
**
** ^(The amount of space allocated by sqlcipher3_aggregate_context(C,N) is
** determined by the N parameter on first successful call.  Changing the
** value of N in subsequent call to sqlcipher3_aggregate_context() within
** the same aggregate function instance will not resize the memory
** allocation.)^
**
** ^SQLite automatically frees the memory allocated by 
** sqlcipher3_aggregate_context() when the aggregate query concludes.
**
** The first parameter must be a copy of the
** [sqlcipher3_context | SQL function context] that is the first parameter
** to the xStep or xFinal callback routine that implements the aggregate
** function.
**
** This routine must be called from the same thread in which
** the aggregate SQL function is running.
*/
SQLCIPHER_API void *sqlcipher3_aggregate_context(sqlcipher3_context*, int nBytes);

/*
** CAPI3REF: User Data For Functions
**
** ^The sqlcipher3_user_data() interface returns a copy of
** the pointer that was the pUserData parameter (the 5th parameter)
** of the [sqlcipher3_create_function()]
** and [sqlcipher3_create_function16()] routines that originally
** registered the application defined function.
**
** This routine must be called from the same thread in which
** the application-defined function is running.
*/
SQLCIPHER_API void *sqlcipher3_user_data(sqlcipher3_context*);

/*
** CAPI3REF: Database Connection For Functions
**
** ^The sqlcipher3_context_db_handle() interface returns a copy of
** the pointer to the [database connection] (the 1st parameter)
** of the [sqlcipher3_create_function()]
** and [sqlcipher3_create_function16()] routines that originally
** registered the application defined function.
*/
SQLCIPHER_API sqlcipher3 *sqlcipher3_context_db_handle(sqlcipher3_context*);

/*
** CAPI3REF: Function Auxiliary Data
**
** The following two functions may be used by scalar SQL functions to
** associate metadata with argument values. If the same value is passed to
** multiple invocations of the same SQL function during query execution, under
** some circumstances the associated metadata may be preserved. This may
** be used, for example, to add a regular-expression matching scalar
** function. The compiled version of the regular expression is stored as
** metadata associated with the SQL value passed as the regular expression
** pattern.  The compiled regular expression can be reused on multiple
** invocations of the same function so that the original pattern string
** does not need to be recompiled on each invocation.
**
** ^The sqlcipher3_get_auxdata() interface returns a pointer to the metadata
** associated by the sqlcipher3_set_auxdata() function with the Nth argument
** value to the application-defined function. ^If no metadata has been ever
** been set for the Nth argument of the function, or if the corresponding
** function parameter has changed since the meta-data was set,
** then sqlcipher3_get_auxdata() returns a NULL pointer.
**
** ^The sqlcipher3_set_auxdata() interface saves the metadata
** pointed to by its 3rd parameter as the metadata for the N-th
** argument of the application-defined function.  Subsequent
** calls to sqlcipher3_get_auxdata() might return this data, if it has
** not been destroyed.
** ^If it is not NULL, SQLite will invoke the destructor
** function given by the 4th parameter to sqlcipher3_set_auxdata() on
** the metadata when the corresponding function parameter changes
** or when the SQL statement completes, whichever comes first.
**
** SQLite is free to call the destructor and drop metadata on any
** parameter of any function at any time.  ^The only guarantee is that
** the destructor will be called before the metadata is dropped.
**
** ^(In practice, metadata is preserved between function calls for
** expressions that are constant at compile time. This includes literal
** values and [parameters].)^
**
** These routines must be called from the same thread in which
** the SQL function is running.
*/
SQLCIPHER_API void *sqlcipher3_get_auxdata(sqlcipher3_context*, int N);
SQLCIPHER_API void sqlcipher3_set_auxdata(sqlcipher3_context*, int N, void*, void (*)(void*));


/*
** CAPI3REF: Constants Defining Special Destructor Behavior
**
** These are special values for the destructor that is passed in as the
** final argument to routines like [sqlcipher3_result_blob()].  ^If the destructor
** argument is SQLCIPHER_STATIC, it means that the content pointer is constant
** and will never change.  It does not need to be destroyed.  ^The
** SQLCIPHER_TRANSIENT value means that the content will likely change in
** the near future and that SQLite should make its own private copy of
** the content before returning.
**
** The typedef is necessary to work around problems in certain
** C++ compilers.  See ticket #2191.
*/
typedef void (*sqlcipher3_destructor_type)(void*);
#define SQLCIPHER_STATIC      ((sqlcipher3_destructor_type)0)
#define SQLCIPHER_TRANSIENT   ((sqlcipher3_destructor_type)-1)

/*
** CAPI3REF: Setting The Result Of An SQL Function
**
** These routines are used by the xFunc or xFinal callbacks that
** implement SQL functions and aggregates.  See
** [sqlcipher3_create_function()] and [sqlcipher3_create_function16()]
** for additional information.
**
** These functions work very much like the [parameter binding] family of
** functions used to bind values to host parameters in prepared statements.
** Refer to the [SQL parameter] documentation for additional information.
**
** ^The sqlcipher3_result_blob() interface sets the result from
** an application-defined function to be the BLOB whose content is pointed
** to by the second parameter and which is N bytes long where N is the
** third parameter.
**
** ^The sqlcipher3_result_zeroblob() interfaces set the result of
** the application-defined function to be a BLOB containing all zero
** bytes and N bytes in size, where N is the value of the 2nd parameter.
**
** ^The sqlcipher3_result_double() interface sets the result from
** an application-defined function to be a floating point value specified
** by its 2nd argument.
**
** ^The sqlcipher3_result_error() and sqlcipher3_result_error16() functions
** cause the implemented SQL function to throw an exception.
** ^SQLite uses the string pointed to by the
** 2nd parameter of sqlcipher3_result_error() or sqlcipher3_result_error16()
** as the text of an error message.  ^SQLite interprets the error
** message string from sqlcipher3_result_error() as UTF-8. ^SQLite
** interprets the string from sqlcipher3_result_error16() as UTF-16 in native
** byte order.  ^If the third parameter to sqlcipher3_result_error()
** or sqlcipher3_result_error16() is negative then SQLite takes as the error
** message all text up through the first zero character.
** ^If the third parameter to sqlcipher3_result_error() or
** sqlcipher3_result_error16() is non-negative then SQLite takes that many
** bytes (not characters) from the 2nd parameter as the error message.
** ^The sqlcipher3_result_error() and sqlcipher3_result_error16()
** routines make a private copy of the error message text before
** they return.  Hence, the calling function can deallocate or
** modify the text after they return without harm.
** ^The sqlcipher3_result_error_code() function changes the error code
** returned by SQLite as a result of an error in a function.  ^By default,
** the error code is SQLCIPHER_ERROR.  ^A subsequent call to sqlcipher3_result_error()
** or sqlcipher3_result_error16() resets the error code to SQLCIPHER_ERROR.
**
** ^The sqlcipher3_result_toobig() interface causes SQLite to throw an error
** indicating that a string or BLOB is too long to represent.
**
** ^The sqlcipher3_result_nomem() interface causes SQLite to throw an error
** indicating that a memory allocation failed.
**
** ^The sqlcipher3_result_int() interface sets the return value
** of the application-defined function to be the 32-bit signed integer
** value given in the 2nd argument.
** ^The sqlcipher3_result_int64() interface sets the return value
** of the application-defined function to be the 64-bit signed integer
** value given in the 2nd argument.
**
** ^The sqlcipher3_result_null() interface sets the return value
** of the application-defined function to be NULL.
**
** ^The sqlcipher3_result_text(), sqlcipher3_result_text16(),
** sqlcipher3_result_text16le(), and sqlcipher3_result_text16be() interfaces
** set the return value of the application-defined function to be
** a text string which is represented as UTF-8, UTF-16 native byte order,
** UTF-16 little endian, or UTF-16 big endian, respectively.
** ^SQLite takes the text result from the application from
** the 2nd parameter of the sqlcipher3_result_text* interfaces.
** ^If the 3rd parameter to the sqlcipher3_result_text* interfaces
** is negative, then SQLite takes result text from the 2nd parameter
** through the first zero character.
** ^If the 3rd parameter to the sqlcipher3_result_text* interfaces
** is non-negative, then as many bytes (not characters) of the text
** pointed to by the 2nd parameter are taken as the application-defined
** function result.  If the 3rd parameter is non-negative, then it
** must be the byte offset into the string where the NUL terminator would
** appear if the string where NUL terminated.  If any NUL characters occur
** in the string at a byte offset that is less than the value of the 3rd
** parameter, then the resulting string will contain embedded NULs and the
** result of expressions operating on strings with embedded NULs is undefined.
** ^If the 4th parameter to the sqlcipher3_result_text* interfaces
** or sqlcipher3_result_blob is a non-NULL pointer, then SQLite calls that
** function as the destructor on the text or BLOB result when it has
** finished using that result.
** ^If the 4th parameter to the sqlcipher3_result_text* interfaces or to
** sqlcipher3_result_blob is the special constant SQLCIPHER_STATIC, then SQLite
** assumes that the text or BLOB result is in constant space and does not
** copy the content of the parameter nor call a destructor on the content
** when it has finished using that result.
** ^If the 4th parameter to the sqlcipher3_result_text* interfaces
** or sqlcipher3_result_blob is the special constant SQLCIPHER_TRANSIENT
** then SQLite makes a copy of the result into space obtained from
** from [sqlcipher3_malloc()] before it returns.
**
** ^The sqlcipher3_result_value() interface sets the result of
** the application-defined function to be a copy the
** [unprotected sqlcipher3_value] object specified by the 2nd parameter.  ^The
** sqlcipher3_result_value() interface makes a copy of the [sqlcipher3_value]
** so that the [sqlcipher3_value] specified in the parameter may change or
** be deallocated after sqlcipher3_result_value() returns without harm.
** ^A [protected sqlcipher3_value] object may always be used where an
** [unprotected sqlcipher3_value] object is required, so either
** kind of [sqlcipher3_value] object can be used with this interface.
**
** If these routines are called from within the different thread
** than the one containing the application-defined function that received
** the [sqlcipher3_context] pointer, the results are undefined.
*/
SQLCIPHER_API void sqlcipher3_result_blob(sqlcipher3_context*, const void*, int, void(*)(void*));
SQLCIPHER_API void sqlcipher3_result_double(sqlcipher3_context*, double);
SQLCIPHER_API void sqlcipher3_result_error(sqlcipher3_context*, const char*, int);
SQLCIPHER_API void sqlcipher3_result_error16(sqlcipher3_context*, const void*, int);
SQLCIPHER_API void sqlcipher3_result_error_toobig(sqlcipher3_context*);
SQLCIPHER_API void sqlcipher3_result_error_nomem(sqlcipher3_context*);
SQLCIPHER_API void sqlcipher3_result_error_code(sqlcipher3_context*, int);
SQLCIPHER_API void sqlcipher3_result_int(sqlcipher3_context*, int);
SQLCIPHER_API void sqlcipher3_result_int64(sqlcipher3_context*, sqlcipher3_int64);
SQLCIPHER_API void sqlcipher3_result_null(sqlcipher3_context*);
SQLCIPHER_API void sqlcipher3_result_text(sqlcipher3_context*, const char*, int, void(*)(void*));
SQLCIPHER_API void sqlcipher3_result_text16(sqlcipher3_context*, const void*, int, void(*)(void*));
SQLCIPHER_API void sqlcipher3_result_text16le(sqlcipher3_context*, const void*, int,void(*)(void*));
SQLCIPHER_API void sqlcipher3_result_text16be(sqlcipher3_context*, const void*, int,void(*)(void*));
SQLCIPHER_API void sqlcipher3_result_value(sqlcipher3_context*, sqlcipher3_value*);
SQLCIPHER_API void sqlcipher3_result_zeroblob(sqlcipher3_context*, int n);

/*
** CAPI3REF: Define New Collating Sequences
**
** ^These functions add, remove, or modify a [collation] associated
** with the [database connection] specified as the first argument.
**
** ^The name of the collation is a UTF-8 string
** for sqlcipher3_create_collation() and sqlcipher3_create_collation_v2()
** and a UTF-16 string in native byte order for sqlcipher3_create_collation16().
** ^Collation names that compare equal according to [sqlcipher3_strnicmp()] are
** considered to be the same name.
**
** ^(The third argument (eTextRep) must be one of the constants:
** <ul>
** <li> [SQLCIPHER_UTF8],
** <li> [SQLCIPHER_UTF16LE],
** <li> [SQLCIPHER_UTF16BE],
** <li> [SQLCIPHER_UTF16], or
** <li> [SQLCIPHER_UTF16_ALIGNED].
** </ul>)^
** ^The eTextRep argument determines the encoding of strings passed
** to the collating function callback, xCallback.
** ^The [SQLCIPHER_UTF16] and [SQLCIPHER_UTF16_ALIGNED] values for eTextRep
** force strings to be UTF16 with native byte order.
** ^The [SQLCIPHER_UTF16_ALIGNED] value for eTextRep forces strings to begin
** on an even byte address.
**
** ^The fourth argument, pArg, is an application data pointer that is passed
** through as the first argument to the collating function callback.
**
** ^The fifth argument, xCallback, is a pointer to the collating function.
** ^Multiple collating functions can be registered using the same name but
** with different eTextRep parameters and SQLite will use whichever
** function requires the least amount of data transformation.
** ^If the xCallback argument is NULL then the collating function is
** deleted.  ^When all collating functions having the same name are deleted,
** that collation is no longer usable.
**
** ^The collating function callback is invoked with a copy of the pArg 
** application data pointer and with two strings in the encoding specified
** by the eTextRep argument.  The collating function must return an
** integer that is negative, zero, or positive
** if the first string is less than, equal to, or greater than the second,
** respectively.  A collating function must always return the same answer
** given the same inputs.  If two or more collating functions are registered
** to the same collation name (using different eTextRep values) then all
** must give an equivalent answer when invoked with equivalent strings.
** The collating function must obey the following properties for all
** strings A, B, and C:
**
** <ol>
** <li> If A==B then B==A.
** <li> If A==B and B==C then A==C.
** <li> If A&lt;B THEN B&gt;A.
** <li> If A&lt;B and B&lt;C then A&lt;C.
** </ol>
**
** If a collating function fails any of the above constraints and that
** collating function is  registered and used, then the behavior of SQLite
** is undefined.
**
** ^The sqlcipher3_create_collation_v2() works like sqlcipher3_create_collation()
** with the addition that the xDestroy callback is invoked on pArg when
** the collating function is deleted.
** ^Collating functions are deleted when they are overridden by later
** calls to the collation creation functions or when the
** [database connection] is closed using [sqlcipher3_close()].
**
** ^The xDestroy callback is <u>not</u> called if the 
** sqlcipher3_create_collation_v2() function fails.  Applications that invoke
** sqlcipher3_create_collation_v2() with a non-NULL xDestroy argument should 
** check the return code and dispose of the application data pointer
** themselves rather than expecting SQLite to deal with it for them.
** This is different from every other SQLite interface.  The inconsistency 
** is unfortunate but cannot be changed without breaking backwards 
** compatibility.
**
** See also:  [sqlcipher3_collation_needed()] and [sqlcipher3_collation_needed16()].
*/
SQLCIPHER_API int sqlcipher3_create_collation(
  sqlcipher3*, 
  const char *zName, 
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*)
);
SQLCIPHER_API int sqlcipher3_create_collation_v2(
  sqlcipher3*, 
  const char *zName, 
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*),
  void(*xDestroy)(void*)
);
SQLCIPHER_API int sqlcipher3_create_collation16(
  sqlcipher3*, 
  const void *zName,
  int eTextRep, 
  void *pArg,
  int(*xCompare)(void*,int,const void*,int,const void*)
);

/*
** CAPI3REF: Collation Needed Callbacks
**
** ^To avoid having to register all collation sequences before a database
** can be used, a single callback function may be registered with the
** [database connection] to be invoked whenever an undefined collation
** sequence is required.
**
** ^If the function is registered using the sqlcipher3_collation_needed() API,
** then it is passed the names of undefined collation sequences as strings
** encoded in UTF-8. ^If sqlcipher3_collation_needed16() is used,
** the names are passed as UTF-16 in machine native byte order.
** ^A call to either function replaces the existing collation-needed callback.
**
** ^(When the callback is invoked, the first argument passed is a copy
** of the second argument to sqlcipher3_collation_needed() or
** sqlcipher3_collation_needed16().  The second argument is the database
** connection.  The third argument is one of [SQLCIPHER_UTF8], [SQLCIPHER_UTF16BE],
** or [SQLCIPHER_UTF16LE], indicating the most desirable form of the collation
** sequence function required.  The fourth parameter is the name of the
** required collation sequence.)^
**
** The callback function should register the desired collation using
** [sqlcipher3_create_collation()], [sqlcipher3_create_collation16()], or
** [sqlcipher3_create_collation_v2()].
*/
SQLCIPHER_API int sqlcipher3_collation_needed(
  sqlcipher3*, 
  void*, 
  void(*)(void*,sqlcipher3*,int eTextRep,const char*)
);
SQLCIPHER_API int sqlcipher3_collation_needed16(
  sqlcipher3*, 
  void*,
  void(*)(void*,sqlcipher3*,int eTextRep,const void*)
);

#ifdef SQLCIPHER_HAS_CODEC
/*
** Specify the key for an encrypted database.  This routine should be
** called right after sqlcipher3_open().
**
** The code to implement this API is not available in the public release
** of SQLite.
*/
SQLCIPHER_API int sqlcipher3_key(
  sqlcipher3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The key */
);

/*
** Change the key on an open database.  If the current database is not
** encrypted, this routine will encrypt it.  If pNew==0 or nNew==0, the
** database is decrypted.
**
** The code to implement this API is not available in the public release
** of SQLite.
*/
SQLCIPHER_API int sqlcipher3_rekey(
  sqlcipher3 *db,                   /* Database to be rekeyed */
  const void *pKey, int nKey     /* The new key */
);

/*
** Specify the activation key for a SEE database.  Unless 
** activated, none of the SEE routines will work.
*/
SQLCIPHER_API void sqlcipher3_activate_see(
  const char *zPassPhrase        /* Activation phrase */
);
#endif

#ifdef SQLCIPHER_ENABLE_CEROD
/*
** Specify the activation key for a CEROD database.  Unless 
** activated, none of the CEROD routines will work.
*/
SQLCIPHER_API void sqlcipher3_activate_cerod(
  const char *zPassPhrase        /* Activation phrase */
);
#endif

/*
** CAPI3REF: Suspend Execution For A Short Time
**
** The sqlcipher3_sleep() function causes the current thread to suspend execution
** for at least a number of milliseconds specified in its parameter.
**
** If the operating system does not support sleep requests with
** millisecond time resolution, then the time will be rounded up to
** the nearest second. The number of milliseconds of sleep actually
** requested from the operating system is returned.
**
** ^SQLite implements this interface by calling the xSleep()
** method of the default [sqlcipher3_vfs] object.  If the xSleep() method
** of the default VFS is not implemented correctly, or not implemented at
** all, then the behavior of sqlcipher3_sleep() may deviate from the description
** in the previous paragraphs.
*/
SQLCIPHER_API int sqlcipher3_sleep(int);

/*
** CAPI3REF: Name Of The Folder Holding Temporary Files
**
** ^(If this global variable is made to point to a string which is
** the name of a folder (a.k.a. directory), then all temporary files
** created by SQLite when using a built-in [sqlcipher3_vfs | VFS]
** will be placed in that directory.)^  ^If this variable
** is a NULL pointer, then SQLite performs a search for an appropriate
** temporary file directory.
**
** It is not safe to read or modify this variable in more than one
** thread at a time.  It is not safe to read or modify this variable
** if a [database connection] is being used at the same time in a separate
** thread.
** It is intended that this variable be set once
** as part of process initialization and before any SQLite interface
** routines have been called and that this variable remain unchanged
** thereafter.
**
** ^The [temp_store_directory pragma] may modify this variable and cause
** it to point to memory obtained from [sqlcipher3_malloc].  ^Furthermore,
** the [temp_store_directory pragma] always assumes that any string
** that this variable points to is held in memory obtained from 
** [sqlcipher3_malloc] and the pragma may attempt to free that memory
** using [sqlcipher3_free].
** Hence, if this variable is modified directly, either it should be
** made NULL or made to point to memory obtained from [sqlcipher3_malloc]
** or else the use of the [temp_store_directory pragma] should be avoided.
*/
SQLCIPHER_API SQLCIPHER_EXTERN char *sqlcipher3_temp_directory;

/*
** CAPI3REF: Test For Auto-Commit Mode
** KEYWORDS: {autocommit mode}
**
** ^The sqlcipher3_get_autocommit() interface returns non-zero or
** zero if the given database connection is or is not in autocommit mode,
** respectively.  ^Autocommit mode is on by default.
** ^Autocommit mode is disabled by a [BEGIN] statement.
** ^Autocommit mode is re-enabled by a [COMMIT] or [ROLLBACK].
**
** If certain kinds of errors occur on a statement within a multi-statement
** transaction (errors including [SQLCIPHER_FULL], [SQLCIPHER_IOERR],
** [SQLCIPHER_NOMEM], [SQLCIPHER_BUSY], and [SQLCIPHER_INTERRUPT]) then the
** transaction might be rolled back automatically.  The only way to
** find out whether SQLite automatically rolled back the transaction after
** an error is to use this function.
**
** If another thread changes the autocommit status of the database
** connection while this routine is running, then the return value
** is undefined.
*/
SQLCIPHER_API int sqlcipher3_get_autocommit(sqlcipher3*);

/*
** CAPI3REF: Find The Database Handle Of A Prepared Statement
**
** ^The sqlcipher3_db_handle interface returns the [database connection] handle
** to which a [prepared statement] belongs.  ^The [database connection]
** returned by sqlcipher3_db_handle is the same [database connection]
** that was the first argument
** to the [sqlcipher3_prepare_v2()] call (or its variants) that was used to
** create the statement in the first place.
*/
SQLCIPHER_API sqlcipher3 *sqlcipher3_db_handle(sqlcipher3_stmt*);

/*
** CAPI3REF: Find the next prepared statement
**
** ^This interface returns a pointer to the next [prepared statement] after
** pStmt associated with the [database connection] pDb.  ^If pStmt is NULL
** then this interface returns a pointer to the first prepared statement
** associated with the database connection pDb.  ^If no prepared statement
** satisfies the conditions of this routine, it returns NULL.
**
** The [database connection] pointer D in a call to
** [sqlcipher3_next_stmt(D,S)] must refer to an open database
** connection and in particular must not be a NULL pointer.
*/
SQLCIPHER_API sqlcipher3_stmt *sqlcipher3_next_stmt(sqlcipher3 *pDb, sqlcipher3_stmt *pStmt);

/*
** CAPI3REF: Commit And Rollback Notification Callbacks
**
** ^The sqlcipher3_commit_hook() interface registers a callback
** function to be invoked whenever a transaction is [COMMIT | committed].
** ^Any callback set by a previous call to sqlcipher3_commit_hook()
** for the same database connection is overridden.
** ^The sqlcipher3_rollback_hook() interface registers a callback
** function to be invoked whenever a transaction is [ROLLBACK | rolled back].
** ^Any callback set by a previous call to sqlcipher3_rollback_hook()
** for the same database connection is overridden.
** ^The pArg argument is passed through to the callback.
** ^If the callback on a commit hook function returns non-zero,
** then the commit is converted into a rollback.
**
** ^The sqlcipher3_commit_hook(D,C,P) and sqlcipher3_rollback_hook(D,C,P) functions
** return the P argument from the previous call of the same function
** on the same [database connection] D, or NULL for
** the first call for each function on D.
**
** The callback implementation must not do anything that will modify
** the database connection that invoked the callback.  Any actions
** to modify the database connection must be deferred until after the
** completion of the [sqlcipher3_step()] call that triggered the commit
** or rollback hook in the first place.
** Note that [sqlcipher3_prepare_v2()] and [sqlcipher3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
** ^Registering a NULL function disables the callback.
**
** ^When the commit hook callback routine returns zero, the [COMMIT]
** operation is allowed to continue normally.  ^If the commit hook
** returns non-zero, then the [COMMIT] is converted into a [ROLLBACK].
** ^The rollback hook is invoked on a rollback that results from a commit
** hook returning non-zero, just as it would be with any other rollback.
**
** ^For the purposes of this API, a transaction is said to have been
** rolled back if an explicit "ROLLBACK" statement is executed, or
** an error or constraint causes an implicit rollback to occur.
** ^The rollback callback is not invoked if a transaction is
** automatically rolled back because the database connection is closed.
**
** See also the [sqlcipher3_update_hook()] interface.
*/
SQLCIPHER_API void *sqlcipher3_commit_hook(sqlcipher3*, int(*)(void*), void*);
SQLCIPHER_API void *sqlcipher3_rollback_hook(sqlcipher3*, void(*)(void *), void*);

/*
** CAPI3REF: Data Change Notification Callbacks
**
** ^The sqlcipher3_update_hook() interface registers a callback function
** with the [database connection] identified by the first argument
** to be invoked whenever a row is updated, inserted or deleted.
** ^Any callback set by a previous call to this function
** for the same database connection is overridden.
**
** ^The second argument is a pointer to the function to invoke when a
** row is updated, inserted or deleted.
** ^The first argument to the callback is a copy of the third argument
** to sqlcipher3_update_hook().
** ^The second callback argument is one of [SQLCIPHER_INSERT], [SQLCIPHER_DELETE],
** or [SQLCIPHER_UPDATE], depending on the operation that caused the callback
** to be invoked.
** ^The third and fourth arguments to the callback contain pointers to the
** database and table name containing the affected row.
** ^The final callback parameter is the [rowid] of the row.
** ^In the case of an update, this is the [rowid] after the update takes place.
**
** ^(The update hook is not invoked when internal system tables are
** modified (i.e. sqlcipher_master and sqlcipher_sequence).)^
**
** ^In the current implementation, the update hook
** is not invoked when duplication rows are deleted because of an
** [ON CONFLICT | ON CONFLICT REPLACE] clause.  ^Nor is the update hook
** invoked when rows are deleted using the [truncate optimization].
** The exceptions defined in this paragraph might change in a future
** release of SQLite.
**
** The update hook implementation must not do anything that will modify
** the database connection that invoked the update hook.  Any actions
** to modify the database connection must be deferred until after the
** completion of the [sqlcipher3_step()] call that triggered the update hook.
** Note that [sqlcipher3_prepare_v2()] and [sqlcipher3_step()] both modify their
** database connections for the meaning of "modify" in this paragraph.
**
** ^The sqlcipher3_update_hook(D,C,P) function
** returns the P argument from the previous call
** on the same [database connection] D, or NULL for
** the first call on D.
**
** See also the [sqlcipher3_commit_hook()] and [sqlcipher3_rollback_hook()]
** interfaces.
*/
SQLCIPHER_API void *sqlcipher3_update_hook(
  sqlcipher3*, 
  void(*)(void *,int ,char const *,char const *,sqlcipher3_int64),
  void*
);

/*
** CAPI3REF: Enable Or Disable Shared Pager Cache
** KEYWORDS: {shared cache}
**
** ^(This routine enables or disables the sharing of the database cache
** and schema data structures between [database connection | connections]
** to the same database. Sharing is enabled if the argument is true
** and disabled if the argument is false.)^
**
** ^Cache sharing is enabled and disabled for an entire process.
** This is a change as of SQLite version 3.5.0. In prior versions of SQLite,
** sharing was enabled or disabled for each thread separately.
**
** ^(The cache sharing mode set by this interface effects all subsequent
** calls to [sqlcipher3_open()], [sqlcipher3_open_v2()], and [sqlcipher3_open16()].
** Existing database connections continue use the sharing mode
** that was in effect at the time they were opened.)^
**
** ^(This routine returns [SQLCIPHER_OK] if shared cache was enabled or disabled
** successfully.  An [error code] is returned otherwise.)^
**
** ^Shared cache is disabled by default. But this might change in
** future releases of SQLite.  Applications that care about shared
** cache setting should set it explicitly.
**
** See Also:  [SQLite Shared-Cache Mode]
*/
SQLCIPHER_API int sqlcipher3_enable_shared_cache(int);

/*
** CAPI3REF: Attempt To Free Heap Memory
**
** ^The sqlcipher3_release_memory() interface attempts to free N bytes
** of heap memory by deallocating non-essential memory allocations
** held by the database library.   Memory used to cache database
** pages to improve performance is an example of non-essential memory.
** ^sqlcipher3_release_memory() returns the number of bytes actually freed,
** which might be more or less than the amount requested.
** ^The sqlcipher3_release_memory() routine is a no-op returning zero
** if SQLite is not compiled with [SQLCIPHER_ENABLE_MEMORY_MANAGEMENT].
*/
SQLCIPHER_API int sqlcipher3_release_memory(int);

/*
** CAPI3REF: Impose A Limit On Heap Size
**
** ^The sqlcipher3_soft_heap_limit64() interface sets and/or queries the
** soft limit on the amount of heap memory that may be allocated by SQLite.
** ^SQLite strives to keep heap memory utilization below the soft heap
** limit by reducing the number of pages held in the page cache
** as heap memory usages approaches the limit.
** ^The soft heap limit is "soft" because even though SQLite strives to stay
** below the limit, it will exceed the limit rather than generate
** an [SQLCIPHER_NOMEM] error.  In other words, the soft heap limit 
** is advisory only.
**
** ^The return value from sqlcipher3_soft_heap_limit64() is the size of
** the soft heap limit prior to the call.  ^If the argument N is negative
** then no change is made to the soft heap limit.  Hence, the current
** size of the soft heap limit can be determined by invoking
** sqlcipher3_soft_heap_limit64() with a negative argument.
**
** ^If the argument N is zero then the soft heap limit is disabled.
**
** ^(The soft heap limit is not enforced in the current implementation
** if one or more of following conditions are true:
**
** <ul>
** <li> The soft heap limit is set to zero.
** <li> Memory accounting is disabled using a combination of the
**      [sqlcipher3_config]([SQLCIPHER_CONFIG_MEMSTATUS],...) start-time option and
**      the [SQLCIPHER_DEFAULT_MEMSTATUS] compile-time option.
** <li> An alternative page cache implementation is specified using
**      [sqlcipher3_config]([SQLCIPHER_CONFIG_PCACHE],...).
** <li> The page cache allocates from its own memory pool supplied
**      by [sqlcipher3_config]([SQLCIPHER_CONFIG_PAGECACHE],...) rather than
**      from the heap.
** </ul>)^
**
** Beginning with SQLite version 3.7.3, the soft heap limit is enforced
** regardless of whether or not the [SQLCIPHER_ENABLE_MEMORY_MANAGEMENT]
** compile-time option is invoked.  With [SQLCIPHER_ENABLE_MEMORY_MANAGEMENT],
** the soft heap limit is enforced on every memory allocation.  Without
** [SQLCIPHER_ENABLE_MEMORY_MANAGEMENT], the soft heap limit is only enforced
** when memory is allocated by the page cache.  Testing suggests that because
** the page cache is the predominate memory user in SQLite, most
** applications will achieve adequate soft heap limit enforcement without
** the use of [SQLCIPHER_ENABLE_MEMORY_MANAGEMENT].
**
** The circumstances under which SQLite will enforce the soft heap limit may
** changes in future releases of SQLite.
*/
SQLCIPHER_API sqlcipher3_int64 sqlcipher3_soft_heap_limit64(sqlcipher3_int64 N);

/*
** CAPI3REF: Deprecated Soft Heap Limit Interface
** DEPRECATED
**
** This is a deprecated version of the [sqlcipher3_soft_heap_limit64()]
** interface.  This routine is provided for historical compatibility
** only.  All new applications should use the
** [sqlcipher3_soft_heap_limit64()] interface rather than this one.
*/
SQLCIPHER_API SQLCIPHER_DEPRECATED void sqlcipher3_soft_heap_limit(int N);


/*
** CAPI3REF: Extract Metadata About A Column Of A Table
**
** ^This routine returns metadata about a specific column of a specific
** database table accessible using the [database connection] handle
** passed as the first function argument.
**
** ^The column is identified by the second, third and fourth parameters to
** this function. ^The second parameter is either the name of the database
** (i.e. "main", "temp", or an attached database) containing the specified
** table or NULL. ^If it is NULL, then all attached databases are searched
** for the table using the same algorithm used by the database engine to
** resolve unqualified table references.
**
** ^The third and fourth parameters to this function are the table and column
** name of the desired column, respectively. Neither of these parameters
** may be NULL.
**
** ^Metadata is returned by writing to the memory locations passed as the 5th
** and subsequent parameters to this function. ^Any of these arguments may be
** NULL, in which case the corresponding element of metadata is omitted.
**
** ^(<blockquote>
** <table border="1">
** <tr><th> Parameter <th> Output<br>Type <th>  Description
**
** <tr><td> 5th <td> const char* <td> Data type
** <tr><td> 6th <td> const char* <td> Name of default collation sequence
** <tr><td> 7th <td> int         <td> True if column has a NOT NULL constraint
** <tr><td> 8th <td> int         <td> True if column is part of the PRIMARY KEY
** <tr><td> 9th <td> int         <td> True if column is [AUTOINCREMENT]
** </table>
** </blockquote>)^
**
** ^The memory pointed to by the character pointers returned for the
** declaration type and collation sequence is valid only until the next
** call to any SQLite API function.
**
** ^If the specified table is actually a view, an [error code] is returned.
**
** ^If the specified column is "rowid", "oid" or "_rowid_" and an
** [INTEGER PRIMARY KEY] column has been explicitly declared, then the output
** parameters are set for the explicitly declared column. ^(If there is no
** explicitly declared [INTEGER PRIMARY KEY] column, then the output
** parameters are set as follows:
**
** <pre>
**     data type: "INTEGER"
**     collation sequence: "BINARY"
**     not null: 0
**     primary key: 1
**     auto increment: 0
** </pre>)^
**
** ^(This function may load one or more schemas from database files. If an
** error occurs during this process, or if the requested table or column
** cannot be found, an [error code] is returned and an error message left
** in the [database connection] (to be retrieved using sqlcipher3_errmsg()).)^
**
** ^This API is only available if the library was compiled with the
** [SQLCIPHER_ENABLE_COLUMN_METADATA] C-preprocessor symbol defined.
*/
SQLCIPHER_API int sqlcipher3_table_column_metadata(
  sqlcipher3 *db,                /* Connection handle */
  const char *zDbName,        /* Database name or NULL */
  const char *zTableName,     /* Table name */
  const char *zColumnName,    /* Column name */
  char const **pzDataType,    /* OUTPUT: Declared data type */
  char const **pzCollSeq,     /* OUTPUT: Collation sequence name */
  int *pNotNull,              /* OUTPUT: True if NOT NULL constraint exists */
  int *pPrimaryKey,           /* OUTPUT: True if column part of PK */
  int *pAutoinc               /* OUTPUT: True if column is auto-increment */
);

/*
** CAPI3REF: Load An Extension
**
** ^This interface loads an SQLite extension library from the named file.
**
** ^The sqlcipher3_load_extension() interface attempts to load an
** SQLite extension library contained in the file zFile.
**
** ^The entry point is zProc.
** ^zProc may be 0, in which case the name of the entry point
** defaults to "sqlcipher3_extension_init".
** ^The sqlcipher3_load_extension() interface returns
** [SQLCIPHER_OK] on success and [SQLCIPHER_ERROR] if something goes wrong.
** ^If an error occurs and pzErrMsg is not 0, then the
** [sqlcipher3_load_extension()] interface shall attempt to
** fill *pzErrMsg with error message text stored in memory
** obtained from [sqlcipher3_malloc()]. The calling function
** should free this memory by calling [sqlcipher3_free()].
**
** ^Extension loading must be enabled using
** [sqlcipher3_enable_load_extension()] prior to calling this API,
** otherwise an error will be returned.
**
** See also the [load_extension() SQL function].
*/
SQLCIPHER_API int sqlcipher3_load_extension(
  sqlcipher3 *db,          /* Load the extension into this database connection */
  const char *zFile,    /* Name of the shared library containing extension */
  const char *zProc,    /* Entry point.  Derived from zFile if 0 */
  char **pzErrMsg       /* Put error message here if not 0 */
);

/*
** CAPI3REF: Enable Or Disable Extension Loading
**
** ^So as not to open security holes in older applications that are
** unprepared to deal with extension loading, and as a means of disabling
** extension loading while evaluating user-entered SQL, the following API
** is provided to turn the [sqlcipher3_load_extension()] mechanism on and off.
**
** ^Extension loading is off by default. See ticket #1863.
** ^Call the sqlcipher3_enable_load_extension() routine with onoff==1
** to turn extension loading on and call it with onoff==0 to turn
** it back off again.
*/
SQLCIPHER_API int sqlcipher3_enable_load_extension(sqlcipher3 *db, int onoff);

/*
** CAPI3REF: Automatically Load Statically Linked Extensions
**
** ^This interface causes the xEntryPoint() function to be invoked for
** each new [database connection] that is created.  The idea here is that
** xEntryPoint() is the entry point for a statically linked SQLite extension
** that is to be automatically loaded into all new database connections.
**
** ^(Even though the function prototype shows that xEntryPoint() takes
** no arguments and returns void, SQLite invokes xEntryPoint() with three
** arguments and expects and integer result as if the signature of the
** entry point where as follows:
**
** <blockquote><pre>
** &nbsp;  int xEntryPoint(
** &nbsp;    sqlcipher3 *db,
** &nbsp;    const char **pzErrMsg,
** &nbsp;    const struct sqlcipher3_api_routines *pThunk
** &nbsp;  );
** </pre></blockquote>)^
**
** If the xEntryPoint routine encounters an error, it should make *pzErrMsg
** point to an appropriate error message (obtained from [sqlcipher3_mprintf()])
** and return an appropriate [error code].  ^SQLite ensures that *pzErrMsg
** is NULL before calling the xEntryPoint().  ^SQLite will invoke
** [sqlcipher3_free()] on *pzErrMsg after xEntryPoint() returns.  ^If any
** xEntryPoint() returns an error, the [sqlcipher3_open()], [sqlcipher3_open16()],
** or [sqlcipher3_open_v2()] call that provoked the xEntryPoint() will fail.
**
** ^Calling sqlcipher3_auto_extension(X) with an entry point X that is already
** on the list of automatic extensions is a harmless no-op. ^No entry point
** will be called more than once for each database connection that is opened.
**
** See also: [sqlcipher3_reset_auto_extension()].
*/
SQLCIPHER_API int sqlcipher3_auto_extension(void (*xEntryPoint)(void));

/*
** CAPI3REF: Reset Automatic Extension Loading
**
** ^This interface disables all automatic extensions previously
** registered using [sqlcipher3_auto_extension()].
*/
SQLCIPHER_API void sqlcipher3_reset_auto_extension(void);

/*
** The interface to the virtual-table mechanism is currently considered
** to be experimental.  The interface might change in incompatible ways.
** If this is a problem for you, do not use the interface at this time.
**
** When the virtual-table mechanism stabilizes, we will declare the
** interface fixed, support it indefinitely, and remove this comment.
*/

/*
** Structures used by the virtual table interface
*/
typedef struct sqlcipher3_vtab sqlcipher3_vtab;
typedef struct sqlcipher3_index_info sqlcipher3_index_info;
typedef struct sqlcipher3_vtab_cursor sqlcipher3_vtab_cursor;
typedef struct sqlcipher3_module sqlcipher3_module;

/*
** CAPI3REF: Virtual Table Object
** KEYWORDS: sqlcipher3_module {virtual table module}
**
** This structure, sometimes called a "virtual table module", 
** defines the implementation of a [virtual tables].  
** This structure consists mostly of methods for the module.
**
** ^A virtual table module is created by filling in a persistent
** instance of this structure and passing a pointer to that instance
** to [sqlcipher3_create_module()] or [sqlcipher3_create_module_v2()].
** ^The registration remains valid until it is replaced by a different
** module or until the [database connection] closes.  The content
** of this structure must not change while it is registered with
** any database connection.
*/
struct sqlcipher3_module {
  int iVersion;
  int (*xCreate)(sqlcipher3*, void *pAux,
               int argc, const char *const*argv,
               sqlcipher3_vtab **ppVTab, char**);
  int (*xConnect)(sqlcipher3*, void *pAux,
               int argc, const char *const*argv,
               sqlcipher3_vtab **ppVTab, char**);
  int (*xBestIndex)(sqlcipher3_vtab *pVTab, sqlcipher3_index_info*);
  int (*xDisconnect)(sqlcipher3_vtab *pVTab);
  int (*xDestroy)(sqlcipher3_vtab *pVTab);
  int (*xOpen)(sqlcipher3_vtab *pVTab, sqlcipher3_vtab_cursor **ppCursor);
  int (*xClose)(sqlcipher3_vtab_cursor*);
  int (*xFilter)(sqlcipher3_vtab_cursor*, int idxNum, const char *idxStr,
                int argc, sqlcipher3_value **argv);
  int (*xNext)(sqlcipher3_vtab_cursor*);
  int (*xEof)(sqlcipher3_vtab_cursor*);
  int (*xColumn)(sqlcipher3_vtab_cursor*, sqlcipher3_context*, int);
  int (*xRowid)(sqlcipher3_vtab_cursor*, sqlcipher3_int64 *pRowid);
  int (*xUpdate)(sqlcipher3_vtab *, int, sqlcipher3_value **, sqlcipher3_int64 *);
  int (*xBegin)(sqlcipher3_vtab *pVTab);
  int (*xSync)(sqlcipher3_vtab *pVTab);
  int (*xCommit)(sqlcipher3_vtab *pVTab);
  int (*xRollback)(sqlcipher3_vtab *pVTab);
  int (*xFindFunction)(sqlcipher3_vtab *pVtab, int nArg, const char *zName,
                       void (**pxFunc)(sqlcipher3_context*,int,sqlcipher3_value**),
                       void **ppArg);
  int (*xRename)(sqlcipher3_vtab *pVtab, const char *zNew);
  /* The methods above are in version 1 of the sqlcipher_module object. Those 
  ** below are for version 2 and greater. */
  int (*xSavepoint)(sqlcipher3_vtab *pVTab, int);
  int (*xRelease)(sqlcipher3_vtab *pVTab, int);
  int (*xRollbackTo)(sqlcipher3_vtab *pVTab, int);
};

/*
** CAPI3REF: Virtual Table Indexing Information
** KEYWORDS: sqlcipher3_index_info
**
** The sqlcipher3_index_info structure and its substructures is used as part
** of the [virtual table] interface to
** pass information into and receive the reply from the [xBestIndex]
** method of a [virtual table module].  The fields under **Inputs** are the
** inputs to xBestIndex and are read-only.  xBestIndex inserts its
** results into the **Outputs** fields.
**
** ^(The aConstraint[] array records WHERE clause constraints of the form:
**
** <blockquote>column OP expr</blockquote>
**
** where OP is =, &lt;, &lt;=, &gt;, or &gt;=.)^  ^(The particular operator is
** stored in aConstraint[].op using one of the
** [SQLCIPHER_INDEX_CONSTRAINT_EQ | SQLCIPHER_INDEX_CONSTRAINT_ values].)^
** ^(The index of the column is stored in
** aConstraint[].iColumn.)^  ^(aConstraint[].usable is TRUE if the
** expr on the right-hand side can be evaluated (and thus the constraint
** is usable) and false if it cannot.)^
**
** ^The optimizer automatically inverts terms of the form "expr OP column"
** and makes other simplifications to the WHERE clause in an attempt to
** get as many WHERE clause terms into the form shown above as possible.
** ^The aConstraint[] array only reports WHERE clause terms that are
** relevant to the particular virtual table being queried.
**
** ^Information about the ORDER BY clause is stored in aOrderBy[].
** ^Each term of aOrderBy records a column of the ORDER BY clause.
**
** The [xBestIndex] method must fill aConstraintUsage[] with information
** about what parameters to pass to xFilter.  ^If argvIndex>0 then
** the right-hand side of the corresponding aConstraint[] is evaluated
** and becomes the argvIndex-th entry in argv.  ^(If aConstraintUsage[].omit
** is true, then the constraint is assumed to be fully handled by the
** virtual table and is not checked again by SQLite.)^
**
** ^The idxNum and idxPtr values are recorded and passed into the
** [xFilter] method.
** ^[sqlcipher3_free()] is used to free idxPtr if and only if
** needToFreeIdxPtr is true.
**
** ^The orderByConsumed means that output from [xFilter]/[xNext] will occur in
** the correct order to satisfy the ORDER BY clause so that no separate
** sorting step is required.
**
** ^The estimatedCost value is an estimate of the cost of doing the
** particular lookup.  A full scan of a table with N entries should have
** a cost of N.  A binary search of a table of N entries should have a
** cost of approximately log(N).
*/
struct sqlcipher3_index_info {
  /* Inputs */
  int nConstraint;           /* Number of entries in aConstraint */
  struct sqlcipher3_index_constraint {
     int iColumn;              /* Column on left-hand side of constraint */
     unsigned char op;         /* Constraint operator */
     unsigned char usable;     /* True if this constraint is usable */
     int iTermOffset;          /* Used internally - xBestIndex should ignore */
  } *aConstraint;            /* Table of WHERE clause constraints */
  int nOrderBy;              /* Number of terms in the ORDER BY clause */
  struct sqlcipher3_index_orderby {
     int iColumn;              /* Column number */
     unsigned char desc;       /* True for DESC.  False for ASC. */
  } *aOrderBy;               /* The ORDER BY clause */
  /* Outputs */
  struct sqlcipher3_index_constraint_usage {
    int argvIndex;           /* if >0, constraint is part of argv to xFilter */
    unsigned char omit;      /* Do not code a test for this constraint */
  } *aConstraintUsage;
  int idxNum;                /* Number used to identify the index */
  char *idxStr;              /* String, possibly obtained from sqlcipher3_malloc */
  int needToFreeIdxStr;      /* Free idxStr using sqlcipher3_free() if true */
  int orderByConsumed;       /* True if output is already ordered */
  double estimatedCost;      /* Estimated cost of using this index */
};

/*
** CAPI3REF: Virtual Table Constraint Operator Codes
**
** These macros defined the allowed values for the
** [sqlcipher3_index_info].aConstraint[].op field.  Each value represents
** an operator that is part of a constraint term in the wHERE clause of
** a query that uses a [virtual table].
*/
#define SQLCIPHER_INDEX_CONSTRAINT_EQ    2
#define SQLCIPHER_INDEX_CONSTRAINT_GT    4
#define SQLCIPHER_INDEX_CONSTRAINT_LE    8
#define SQLCIPHER_INDEX_CONSTRAINT_LT    16
#define SQLCIPHER_INDEX_CONSTRAINT_GE    32
#define SQLCIPHER_INDEX_CONSTRAINT_MATCH 64

/*
** CAPI3REF: Register A Virtual Table Implementation
**
** ^These routines are used to register a new [virtual table module] name.
** ^Module names must be registered before
** creating a new [virtual table] using the module and before using a
** preexisting [virtual table] for the module.
**
** ^The module name is registered on the [database connection] specified
** by the first parameter.  ^The name of the module is given by the 
** second parameter.  ^The third parameter is a pointer to
** the implementation of the [virtual table module].   ^The fourth
** parameter is an arbitrary client data pointer that is passed through
** into the [xCreate] and [xConnect] methods of the virtual table module
** when a new virtual table is be being created or reinitialized.
**
** ^The sqlcipher3_create_module_v2() interface has a fifth parameter which
** is a pointer to a destructor for the pClientData.  ^SQLite will
** invoke the destructor function (if it is not NULL) when SQLite
** no longer needs the pClientData pointer.  ^The destructor will also
** be invoked if the call to sqlcipher3_create_module_v2() fails.
** ^The sqlcipher3_create_module()
** interface is equivalent to sqlcipher3_create_module_v2() with a NULL
** destructor.
*/
SQLCIPHER_API int sqlcipher3_create_module(
  sqlcipher3 *db,               /* SQLite connection to register module with */
  const char *zName,         /* Name of the module */
  const sqlcipher3_module *p,   /* Methods for the module */
  void *pClientData          /* Client data for xCreate/xConnect */
);
SQLCIPHER_API int sqlcipher3_create_module_v2(
  sqlcipher3 *db,               /* SQLite connection to register module with */
  const char *zName,         /* Name of the module */
  const sqlcipher3_module *p,   /* Methods for the module */
  void *pClientData,         /* Client data for xCreate/xConnect */
  void(*xDestroy)(void*)     /* Module destructor function */
);

/*
** CAPI3REF: Virtual Table Instance Object
** KEYWORDS: sqlcipher3_vtab
**
** Every [virtual table module] implementation uses a subclass
** of this object to describe a particular instance
** of the [virtual table].  Each subclass will
** be tailored to the specific needs of the module implementation.
** The purpose of this superclass is to define certain fields that are
** common to all module implementations.
**
** ^Virtual tables methods can set an error message by assigning a
** string obtained from [sqlcipher3_mprintf()] to zErrMsg.  The method should
** take care that any prior string is freed by a call to [sqlcipher3_free()]
** prior to assigning a new string to zErrMsg.  ^After the error message
** is delivered up to the client application, the string will be automatically
** freed by sqlcipher3_free() and the zErrMsg field will be zeroed.
*/
struct sqlcipher3_vtab {
  const sqlcipher3_module *pModule;  /* The module for this virtual table */
  int nRef;                       /* NO LONGER USED */
  char *zErrMsg;                  /* Error message from sqlcipher3_mprintf() */
  /* Virtual table implementations will typically add additional fields */
};

/*
** CAPI3REF: Virtual Table Cursor Object
** KEYWORDS: sqlcipher3_vtab_cursor {virtual table cursor}
**
** Every [virtual table module] implementation uses a subclass of the
** following structure to describe cursors that point into the
** [virtual table] and are used
** to loop through the virtual table.  Cursors are created using the
** [sqlcipher3_module.xOpen | xOpen] method of the module and are destroyed
** by the [sqlcipher3_module.xClose | xClose] method.  Cursors are used
** by the [xFilter], [xNext], [xEof], [xColumn], and [xRowid] methods
** of the module.  Each module implementation will define
** the content of a cursor structure to suit its own needs.
**
** This superclass exists in order to define fields of the cursor that
** are common to all implementations.
*/
struct sqlcipher3_vtab_cursor {
  sqlcipher3_vtab *pVtab;      /* Virtual table of this cursor */
  /* Virtual table implementations will typically add additional fields */
};

/*
** CAPI3REF: Declare The Schema Of A Virtual Table
**
** ^The [xCreate] and [xConnect] methods of a
** [virtual table module] call this interface
** to declare the format (the names and datatypes of the columns) of
** the virtual tables they implement.
*/
SQLCIPHER_API int sqlcipher3_declare_vtab(sqlcipher3*, const char *zSQL);

/*
** CAPI3REF: Overload A Function For A Virtual Table
**
** ^(Virtual tables can provide alternative implementations of functions
** using the [xFindFunction] method of the [virtual table module].  
** But global versions of those functions
** must exist in order to be overloaded.)^
**
** ^(This API makes sure a global version of a function with a particular
** name and number of parameters exists.  If no such function exists
** before this API is called, a new function is created.)^  ^The implementation
** of the new function always causes an exception to be thrown.  So
** the new function is not good for anything by itself.  Its only
** purpose is to be a placeholder function that can be overloaded
** by a [virtual table].
*/
SQLCIPHER_API int sqlcipher3_overload_function(sqlcipher3*, const char *zFuncName, int nArg);

/*
** The interface to the virtual-table mechanism defined above (back up
** to a comment remarkably similar to this one) is currently considered
** to be experimental.  The interface might change in incompatible ways.
** If this is a problem for you, do not use the interface at this time.
**
** When the virtual-table mechanism stabilizes, we will declare the
** interface fixed, support it indefinitely, and remove this comment.
*/

/*
** CAPI3REF: A Handle To An Open BLOB
** KEYWORDS: {BLOB handle} {BLOB handles}
**
** An instance of this object represents an open BLOB on which
** [sqlcipher3_blob_open | incremental BLOB I/O] can be performed.
** ^Objects of this type are created by [sqlcipher3_blob_open()]
** and destroyed by [sqlcipher3_blob_close()].
** ^The [sqlcipher3_blob_read()] and [sqlcipher3_blob_write()] interfaces
** can be used to read or write small subsections of the BLOB.
** ^The [sqlcipher3_blob_bytes()] interface returns the size of the BLOB in bytes.
*/
typedef struct sqlcipher3_blob sqlcipher3_blob;

/*
** CAPI3REF: Open A BLOB For Incremental I/O
**
** ^(This interfaces opens a [BLOB handle | handle] to the BLOB located
** in row iRow, column zColumn, table zTable in database zDb;
** in other words, the same BLOB that would be selected by:
**
** <pre>
**     SELECT zColumn FROM zDb.zTable WHERE [rowid] = iRow;
** </pre>)^
**
** ^If the flags parameter is non-zero, then the BLOB is opened for read
** and write access. ^If it is zero, the BLOB is opened for read access.
** ^It is not possible to open a column that is part of an index or primary 
** key for writing. ^If [foreign key constraints] are enabled, it is 
** not possible to open a column that is part of a [child key] for writing.
**
** ^Note that the database name is not the filename that contains
** the database but rather the symbolic name of the database that
** appears after the AS keyword when the database is connected using [ATTACH].
** ^For the main database file, the database name is "main".
** ^For TEMP tables, the database name is "temp".
**
** ^(On success, [SQLCIPHER_OK] is returned and the new [BLOB handle] is written
** to *ppBlob. Otherwise an [error code] is returned and *ppBlob is set
** to be a null pointer.)^
** ^This function sets the [database connection] error code and message
** accessible via [sqlcipher3_errcode()] and [sqlcipher3_errmsg()] and related
** functions. ^Note that the *ppBlob variable is always initialized in a
** way that makes it safe to invoke [sqlcipher3_blob_close()] on *ppBlob
** regardless of the success or failure of this routine.
**
** ^(If the row that a BLOB handle points to is modified by an
** [UPDATE], [DELETE], or by [ON CONFLICT] side-effects
** then the BLOB handle is marked as "expired".
** This is true if any column of the row is changed, even a column
** other than the one the BLOB handle is open on.)^
** ^Calls to [sqlcipher3_blob_read()] and [sqlcipher3_blob_write()] for
** an expired BLOB handle fail with a return code of [SQLCIPHER_ABORT].
** ^(Changes written into a BLOB prior to the BLOB expiring are not
** rolled back by the expiration of the BLOB.  Such changes will eventually
** commit if the transaction continues to completion.)^
**
** ^Use the [sqlcipher3_blob_bytes()] interface to determine the size of
** the opened blob.  ^The size of a blob may not be changed by this
** interface.  Use the [UPDATE] SQL command to change the size of a
** blob.
**
** ^The [sqlcipher3_bind_zeroblob()] and [sqlcipher3_result_zeroblob()] interfaces
** and the built-in [zeroblob] SQL function can be used, if desired,
** to create an empty, zero-filled blob in which to read or write using
** this interface.
**
** To avoid a resource leak, every open [BLOB handle] should eventually
** be released by a call to [sqlcipher3_blob_close()].
*/
SQLCIPHER_API int sqlcipher3_blob_open(
  sqlcipher3*,
  const char *zDb,
  const char *zTable,
  const char *zColumn,
  sqlcipher3_int64 iRow,
  int flags,
  sqlcipher3_blob **ppBlob
);

/*
** CAPI3REF: Move a BLOB Handle to a New Row
**
** ^This function is used to move an existing blob handle so that it points
** to a different row of the same database table. ^The new row is identified
** by the rowid value passed as the second argument. Only the row can be
** changed. ^The database, table and column on which the blob handle is open
** remain the same. Moving an existing blob handle to a new row can be
** faster than closing the existing handle and opening a new one.
**
** ^(The new row must meet the same criteria as for [sqlcipher3_blob_open()] -
** it must exist and there must be either a blob or text value stored in
** the nominated column.)^ ^If the new row is not present in the table, or if
** it does not contain a blob or text value, or if another error occurs, an
** SQLite error code is returned and the blob handle is considered aborted.
** ^All subsequent calls to [sqlcipher3_blob_read()], [sqlcipher3_blob_write()] or
** [sqlcipher3_blob_reopen()] on an aborted blob handle immediately return
** SQLCIPHER_ABORT. ^Calling [sqlcipher3_blob_bytes()] on an aborted blob handle
** always returns zero.
**
** ^This function sets the database handle error code and message.
*/
SQLCIPHER_API SQLCIPHER_EXPERIMENTAL int sqlcipher3_blob_reopen(sqlcipher3_blob *, sqlcipher3_int64);

/*
** CAPI3REF: Close A BLOB Handle
**
** ^Closes an open [BLOB handle].
**
** ^Closing a BLOB shall cause the current transaction to commit
** if there are no other BLOBs, no pending prepared statements, and the
** database connection is in [autocommit mode].
** ^If any writes were made to the BLOB, they might be held in cache
** until the close operation if they will fit.
**
** ^(Closing the BLOB often forces the changes
** out to disk and so if any I/O errors occur, they will likely occur
** at the time when the BLOB is closed.  Any errors that occur during
** closing are reported as a non-zero return value.)^
**
** ^(The BLOB is closed unconditionally.  Even if this routine returns
** an error code, the BLOB is still closed.)^
**
** ^Calling this routine with a null pointer (such as would be returned
** by a failed call to [sqlcipher3_blob_open()]) is a harmless no-op.
*/
SQLCIPHER_API int sqlcipher3_blob_close(sqlcipher3_blob *);

/*
** CAPI3REF: Return The Size Of An Open BLOB
**
** ^Returns the size in bytes of the BLOB accessible via the 
** successfully opened [BLOB handle] in its only argument.  ^The
** incremental blob I/O routines can only read or overwriting existing
** blob content; they cannot change the size of a blob.
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlcipher3_blob_open()] and which has not
** been closed by [sqlcipher3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
*/
SQLCIPHER_API int sqlcipher3_blob_bytes(sqlcipher3_blob *);

/*
** CAPI3REF: Read Data From A BLOB Incrementally
**
** ^(This function is used to read data from an open [BLOB handle] into a
** caller-supplied buffer. N bytes of data are copied into buffer Z
** from the open BLOB, starting at offset iOffset.)^
**
** ^If offset iOffset is less than N bytes from the end of the BLOB,
** [SQLCIPHER_ERROR] is returned and no data is read.  ^If N or iOffset is
** less than zero, [SQLCIPHER_ERROR] is returned and no data is read.
** ^The size of the blob (and hence the maximum value of N+iOffset)
** can be determined using the [sqlcipher3_blob_bytes()] interface.
**
** ^An attempt to read from an expired [BLOB handle] fails with an
** error code of [SQLCIPHER_ABORT].
**
** ^(On success, sqlcipher3_blob_read() returns SQLCIPHER_OK.
** Otherwise, an [error code] or an [extended error code] is returned.)^
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlcipher3_blob_open()] and which has not
** been closed by [sqlcipher3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
**
** See also: [sqlcipher3_blob_write()].
*/
SQLCIPHER_API int sqlcipher3_blob_read(sqlcipher3_blob *, void *Z, int N, int iOffset);

/*
** CAPI3REF: Write Data Into A BLOB Incrementally
**
** ^This function is used to write data into an open [BLOB handle] from a
** caller-supplied buffer. ^N bytes of data are copied from the buffer Z
** into the open BLOB, starting at offset iOffset.
**
** ^If the [BLOB handle] passed as the first argument was not opened for
** writing (the flags parameter to [sqlcipher3_blob_open()] was zero),
** this function returns [SQLCIPHER_READONLY].
**
** ^This function may only modify the contents of the BLOB; it is
** not possible to increase the size of a BLOB using this API.
** ^If offset iOffset is less than N bytes from the end of the BLOB,
** [SQLCIPHER_ERROR] is returned and no data is written.  ^If N is
** less than zero [SQLCIPHER_ERROR] is returned and no data is written.
** The size of the BLOB (and hence the maximum value of N+iOffset)
** can be determined using the [sqlcipher3_blob_bytes()] interface.
**
** ^An attempt to write to an expired [BLOB handle] fails with an
** error code of [SQLCIPHER_ABORT].  ^Writes to the BLOB that occurred
** before the [BLOB handle] expired are not rolled back by the
** expiration of the handle, though of course those changes might
** have been overwritten by the statement that expired the BLOB handle
** or by other independent statements.
**
** ^(On success, sqlcipher3_blob_write() returns SQLCIPHER_OK.
** Otherwise, an  [error code] or an [extended error code] is returned.)^
**
** This routine only works on a [BLOB handle] which has been created
** by a prior successful call to [sqlcipher3_blob_open()] and which has not
** been closed by [sqlcipher3_blob_close()].  Passing any other pointer in
** to this routine results in undefined and probably undesirable behavior.
**
** See also: [sqlcipher3_blob_read()].
*/
SQLCIPHER_API int sqlcipher3_blob_write(sqlcipher3_blob *, const void *z, int n, int iOffset);

/*
** CAPI3REF: Virtual File System Objects
**
** A virtual filesystem (VFS) is an [sqlcipher3_vfs] object
** that SQLite uses to interact
** with the underlying operating system.  Most SQLite builds come with a
** single default VFS that is appropriate for the host computer.
** New VFSes can be registered and existing VFSes can be unregistered.
** The following interfaces are provided.
**
** ^The sqlcipher3_vfs_find() interface returns a pointer to a VFS given its name.
** ^Names are case sensitive.
** ^Names are zero-terminated UTF-8 strings.
** ^If there is no match, a NULL pointer is returned.
** ^If zVfsName is NULL then the default VFS is returned.
**
** ^New VFSes are registered with sqlcipher3_vfs_register().
** ^Each new VFS becomes the default VFS if the makeDflt flag is set.
** ^The same VFS can be registered multiple times without injury.
** ^To make an existing VFS into the default VFS, register it again
** with the makeDflt flag set.  If two different VFSes with the
** same name are registered, the behavior is undefined.  If a
** VFS is registered with a name that is NULL or an empty string,
** then the behavior is undefined.
**
** ^Unregister a VFS with the sqlcipher3_vfs_unregister() interface.
** ^(If the default VFS is unregistered, another VFS is chosen as
** the default.  The choice for the new VFS is arbitrary.)^
*/
SQLCIPHER_API sqlcipher3_vfs *sqlcipher3_vfs_find(const char *zVfsName);
SQLCIPHER_API int sqlcipher3_vfs_register(sqlcipher3_vfs*, int makeDflt);
SQLCIPHER_API int sqlcipher3_vfs_unregister(sqlcipher3_vfs*);

/*
** CAPI3REF: Mutexes
**
** The SQLite core uses these routines for thread
** synchronization. Though they are intended for internal
** use by SQLite, code that links against SQLite is
** permitted to use any of these routines.
**
** The SQLite source code contains multiple implementations
** of these mutex routines.  An appropriate implementation
** is selected automatically at compile-time.  ^(The following
** implementations are available in the SQLite core:
**
** <ul>
** <li>   SQLCIPHER_MUTEX_OS2
** <li>   SQLCIPHER_MUTEX_PTHREAD
** <li>   SQLCIPHER_MUTEX_W32
** <li>   SQLCIPHER_MUTEX_NOOP
** </ul>)^
**
** ^The SQLCIPHER_MUTEX_NOOP implementation is a set of routines
** that does no real locking and is appropriate for use in
** a single-threaded application.  ^The SQLCIPHER_MUTEX_OS2,
** SQLCIPHER_MUTEX_PTHREAD, and SQLCIPHER_MUTEX_W32 implementations
** are appropriate for use on OS/2, Unix, and Windows.
**
** ^(If SQLite is compiled with the SQLCIPHER_MUTEX_APPDEF preprocessor
** macro defined (with "-DSQLCIPHER_MUTEX_APPDEF=1"), then no mutex
** implementation is included with the library. In this case the
** application must supply a custom mutex implementation using the
** [SQLCIPHER_CONFIG_MUTEX] option of the sqlcipher3_config() function
** before calling sqlcipher3_initialize() or any other public sqlcipher3_
** function that calls sqlcipher3_initialize().)^
**
** ^The sqlcipher3_mutex_alloc() routine allocates a new
** mutex and returns a pointer to it. ^If it returns NULL
** that means that a mutex could not be allocated.  ^SQLite
** will unwind its stack and return an error.  ^(The argument
** to sqlcipher3_mutex_alloc() is one of these integer constants:
**
** <ul>
** <li>  SQLCIPHER_MUTEX_FAST
** <li>  SQLCIPHER_MUTEX_RECURSIVE
** <li>  SQLCIPHER_MUTEX_STATIC_MASTER
** <li>  SQLCIPHER_MUTEX_STATIC_MEM
** <li>  SQLCIPHER_MUTEX_STATIC_MEM2
** <li>  SQLCIPHER_MUTEX_STATIC_PRNG
** <li>  SQLCIPHER_MUTEX_STATIC_LRU
** <li>  SQLCIPHER_MUTEX_STATIC_LRU2
** </ul>)^
**
** ^The first two constants (SQLCIPHER_MUTEX_FAST and SQLCIPHER_MUTEX_RECURSIVE)
** cause sqlcipher3_mutex_alloc() to create
** a new mutex.  ^The new mutex is recursive when SQLCIPHER_MUTEX_RECURSIVE
** is used but not necessarily so when SQLCIPHER_MUTEX_FAST is used.
** The mutex implementation does not need to make a distinction
** between SQLCIPHER_MUTEX_RECURSIVE and SQLCIPHER_MUTEX_FAST if it does
** not want to.  ^SQLite will only request a recursive mutex in
** cases where it really needs one.  ^If a faster non-recursive mutex
** implementation is available on the host platform, the mutex subsystem
** might return such a mutex in response to SQLCIPHER_MUTEX_FAST.
**
** ^The other allowed parameters to sqlcipher3_mutex_alloc() (anything other
** than SQLCIPHER_MUTEX_FAST and SQLCIPHER_MUTEX_RECURSIVE) each return
** a pointer to a static preexisting mutex.  ^Six static mutexes are
** used by the current version of SQLite.  Future versions of SQLite
** may add additional static mutexes.  Static mutexes are for internal
** use by SQLite only.  Applications that use SQLite mutexes should
** use only the dynamic mutexes returned by SQLCIPHER_MUTEX_FAST or
** SQLCIPHER_MUTEX_RECURSIVE.
**
** ^Note that if one of the dynamic mutex parameters (SQLCIPHER_MUTEX_FAST
** or SQLCIPHER_MUTEX_RECURSIVE) is used then sqlcipher3_mutex_alloc()
** returns a different mutex on every call.  ^But for the static
** mutex types, the same mutex is returned on every call that has
** the same type number.
**
** ^The sqlcipher3_mutex_free() routine deallocates a previously
** allocated dynamic mutex.  ^SQLite is careful to deallocate every
** dynamic mutex that it allocates.  The dynamic mutexes must not be in
** use when they are deallocated.  Attempting to deallocate a static
** mutex results in undefined behavior.  ^SQLite never deallocates
** a static mutex.
**
** ^The sqlcipher3_mutex_enter() and sqlcipher3_mutex_try() routines attempt
** to enter a mutex.  ^If another thread is already within the mutex,
** sqlcipher3_mutex_enter() will block and sqlcipher3_mutex_try() will return
** SQLCIPHER_BUSY.  ^The sqlcipher3_mutex_try() interface returns [SQLCIPHER_OK]
** upon successful entry.  ^(Mutexes created using
** SQLCIPHER_MUTEX_RECURSIVE can be entered multiple times by the same thread.
** In such cases the,
** mutex must be exited an equal number of times before another thread
** can enter.)^  ^(If the same thread tries to enter any other
** kind of mutex more than once, the behavior is undefined.
** SQLite will never exhibit
** such behavior in its own use of mutexes.)^
**
** ^(Some systems (for example, Windows 95) do not support the operation
** implemented by sqlcipher3_mutex_try().  On those systems, sqlcipher3_mutex_try()
** will always return SQLCIPHER_BUSY.  The SQLite core only ever uses
** sqlcipher3_mutex_try() as an optimization so this is acceptable behavior.)^
**
** ^The sqlcipher3_mutex_leave() routine exits a mutex that was
** previously entered by the same thread.   ^(The behavior
** is undefined if the mutex is not currently entered by the
** calling thread or is not currently allocated.  SQLite will
** never do either.)^
**
** ^If the argument to sqlcipher3_mutex_enter(), sqlcipher3_mutex_try(), or
** sqlcipher3_mutex_leave() is a NULL pointer, then all three routines
** behave as no-ops.
**
** See also: [sqlcipher3_mutex_held()] and [sqlcipher3_mutex_notheld()].
*/
SQLCIPHER_API sqlcipher3_mutex *sqlcipher3_mutex_alloc(int);
SQLCIPHER_API void sqlcipher3_mutex_free(sqlcipher3_mutex*);
SQLCIPHER_API void sqlcipher3_mutex_enter(sqlcipher3_mutex*);
SQLCIPHER_API int sqlcipher3_mutex_try(sqlcipher3_mutex*);
SQLCIPHER_API void sqlcipher3_mutex_leave(sqlcipher3_mutex*);

/*
** CAPI3REF: Mutex Methods Object
**
** An instance of this structure defines the low-level routines
** used to allocate and use mutexes.
**
** Usually, the default mutex implementations provided by SQLite are
** sufficient, however the user has the option of substituting a custom
** implementation for specialized deployments or systems for which SQLite
** does not provide a suitable implementation. In this case, the user
** creates and populates an instance of this structure to pass
** to sqlcipher3_config() along with the [SQLCIPHER_CONFIG_MUTEX] option.
** Additionally, an instance of this structure can be used as an
** output variable when querying the system for the current mutex
** implementation, using the [SQLCIPHER_CONFIG_GETMUTEX] option.
**
** ^The xMutexInit method defined by this structure is invoked as
** part of system initialization by the sqlcipher3_initialize() function.
** ^The xMutexInit routine is called by SQLite exactly once for each
** effective call to [sqlcipher3_initialize()].
**
** ^The xMutexEnd method defined by this structure is invoked as
** part of system shutdown by the sqlcipher3_shutdown() function. The
** implementation of this method is expected to release all outstanding
** resources obtained by the mutex methods implementation, especially
** those obtained by the xMutexInit method.  ^The xMutexEnd()
** interface is invoked exactly once for each call to [sqlcipher3_shutdown()].
**
** ^(The remaining seven methods defined by this structure (xMutexAlloc,
** xMutexFree, xMutexEnter, xMutexTry, xMutexLeave, xMutexHeld and
** xMutexNotheld) implement the following interfaces (respectively):
**
** <ul>
**   <li>  [sqlcipher3_mutex_alloc()] </li>
**   <li>  [sqlcipher3_mutex_free()] </li>
**   <li>  [sqlcipher3_mutex_enter()] </li>
**   <li>  [sqlcipher3_mutex_try()] </li>
**   <li>  [sqlcipher3_mutex_leave()] </li>
**   <li>  [sqlcipher3_mutex_held()] </li>
**   <li>  [sqlcipher3_mutex_notheld()] </li>
** </ul>)^
**
** The only difference is that the public sqlcipher3_XXX functions enumerated
** above silently ignore any invocations that pass a NULL pointer instead
** of a valid mutex handle. The implementations of the methods defined
** by this structure are not required to handle this case, the results
** of passing a NULL pointer instead of a valid mutex handle are undefined
** (i.e. it is acceptable to provide an implementation that segfaults if
** it is passed a NULL pointer).
**
** The xMutexInit() method must be threadsafe.  ^It must be harmless to
** invoke xMutexInit() multiple times within the same process and without
** intervening calls to xMutexEnd().  Second and subsequent calls to
** xMutexInit() must be no-ops.
**
** ^xMutexInit() must not use SQLite memory allocation ([sqlcipher3_malloc()]
** and its associates).  ^Similarly, xMutexAlloc() must not use SQLite memory
** allocation for a static mutex.  ^However xMutexAlloc() may use SQLite
** memory allocation for a fast or recursive mutex.
**
** ^SQLite will invoke the xMutexEnd() method when [sqlcipher3_shutdown()] is
** called, but only if the prior call to xMutexInit returned SQLCIPHER_OK.
** If xMutexInit fails in any way, it is expected to clean up after itself
** prior to returning.
*/
typedef struct sqlcipher3_mutex_methods sqlcipher3_mutex_methods;
struct sqlcipher3_mutex_methods {
  int (*xMutexInit)(void);
  int (*xMutexEnd)(void);
  sqlcipher3_mutex *(*xMutexAlloc)(int);
  void (*xMutexFree)(sqlcipher3_mutex *);
  void (*xMutexEnter)(sqlcipher3_mutex *);
  int (*xMutexTry)(sqlcipher3_mutex *);
  void (*xMutexLeave)(sqlcipher3_mutex *);
  int (*xMutexHeld)(sqlcipher3_mutex *);
  int (*xMutexNotheld)(sqlcipher3_mutex *);
};

/*
** CAPI3REF: Mutex Verification Routines
**
** The sqlcipher3_mutex_held() and sqlcipher3_mutex_notheld() routines
** are intended for use inside assert() statements.  ^The SQLite core
** never uses these routines except inside an assert() and applications
** are advised to follow the lead of the core.  ^The SQLite core only
** provides implementations for these routines when it is compiled
** with the SQLCIPHER_DEBUG flag.  ^External mutex implementations
** are only required to provide these routines if SQLCIPHER_DEBUG is
** defined and if NDEBUG is not defined.
**
** ^These routines should return true if the mutex in their argument
** is held or not held, respectively, by the calling thread.
**
** ^The implementation is not required to provided versions of these
** routines that actually work. If the implementation does not provide working
** versions of these routines, it should at least provide stubs that always
** return true so that one does not get spurious assertion failures.
**
** ^If the argument to sqlcipher3_mutex_held() is a NULL pointer then
** the routine should return 1.   This seems counter-intuitive since
** clearly the mutex cannot be held if it does not exist.  But
** the reason the mutex does not exist is because the build is not
** using mutexes.  And we do not want the assert() containing the
** call to sqlcipher3_mutex_held() to fail, so a non-zero return is
** the appropriate thing to do.  ^The sqlcipher3_mutex_notheld()
** interface should also return 1 when given a NULL pointer.
*/
#ifndef NDEBUG
SQLCIPHER_API int sqlcipher3_mutex_held(sqlcipher3_mutex*);
SQLCIPHER_API int sqlcipher3_mutex_notheld(sqlcipher3_mutex*);
#endif

/*
** CAPI3REF: Mutex Types
**
** The [sqlcipher3_mutex_alloc()] interface takes a single argument
** which is one of these integer constants.
**
** The set of static mutexes may change from one SQLite release to the
** next.  Applications that override the built-in mutex logic must be
** prepared to accommodate additional static mutexes.
*/
#define SQLCIPHER_MUTEX_FAST             0
#define SQLCIPHER_MUTEX_RECURSIVE        1
#define SQLCIPHER_MUTEX_STATIC_MASTER    2
#define SQLCIPHER_MUTEX_STATIC_MEM       3  /* sqlcipher3_malloc() */
#define SQLCIPHER_MUTEX_STATIC_MEM2      4  /* NOT USED */
#define SQLCIPHER_MUTEX_STATIC_OPEN      4  /* sqlcipher3BtreeOpen() */
#define SQLCIPHER_MUTEX_STATIC_PRNG      5  /* sqlcipher3_random() */
#define SQLCIPHER_MUTEX_STATIC_LRU       6  /* lru page list */
#define SQLCIPHER_MUTEX_STATIC_LRU2      7  /* NOT USED */
#define SQLCIPHER_MUTEX_STATIC_PMEM      7  /* sqlcipher3PageMalloc() */

/*
** CAPI3REF: Retrieve the mutex for a database connection
**
** ^This interface returns a pointer the [sqlcipher3_mutex] object that 
** serializes access to the [database connection] given in the argument
** when the [threading mode] is Serialized.
** ^If the [threading mode] is Single-thread or Multi-thread then this
** routine returns a NULL pointer.
*/
SQLCIPHER_API sqlcipher3_mutex *sqlcipher3_db_mutex(sqlcipher3*);

/*
** CAPI3REF: Low-Level Control Of Database Files
**
** ^The [sqlcipher3_file_control()] interface makes a direct call to the
** xFileControl method for the [sqlcipher3_io_methods] object associated
** with a particular database identified by the second argument. ^The
** name of the database is "main" for the main database or "temp" for the
** TEMP database, or the name that appears after the AS keyword for
** databases that are added using the [ATTACH] SQL command.
** ^A NULL pointer can be used in place of "main" to refer to the
** main database file.
** ^The third and fourth parameters to this routine
** are passed directly through to the second and third parameters of
** the xFileControl method.  ^The return value of the xFileControl
** method becomes the return value of this routine.
**
** ^The SQLCIPHER_FCNTL_FILE_POINTER value for the op parameter causes
** a pointer to the underlying [sqlcipher3_file] object to be written into
** the space pointed to by the 4th parameter.  ^The SQLCIPHER_FCNTL_FILE_POINTER
** case is a short-circuit path which does not actually invoke the
** underlying sqlcipher3_io_methods.xFileControl method.
**
** ^If the second parameter (zDbName) does not match the name of any
** open database file, then SQLCIPHER_ERROR is returned.  ^This error
** code is not remembered and will not be recalled by [sqlcipher3_errcode()]
** or [sqlcipher3_errmsg()].  The underlying xFileControl method might
** also return SQLCIPHER_ERROR.  There is no way to distinguish between
** an incorrect zDbName and an SQLCIPHER_ERROR return from the underlying
** xFileControl method.
**
** See also: [SQLCIPHER_FCNTL_LOCKSTATE]
*/
SQLCIPHER_API int sqlcipher3_file_control(sqlcipher3*, const char *zDbName, int op, void*);

/*
** CAPI3REF: Testing Interface
**
** ^The sqlcipher3_test_control() interface is used to read out internal
** state of SQLite and to inject faults into SQLite for testing
** purposes.  ^The first parameter is an operation code that determines
** the number, meaning, and operation of all subsequent parameters.
**
** This interface is not for use by applications.  It exists solely
** for verifying the correct operation of the SQLite library.  Depending
** on how the SQLite library is compiled, this interface might not exist.
**
** The details of the operation codes, their meanings, the parameters
** they take, and what they do are all subject to change without notice.
** Unlike most of the SQLite API, this function is not guaranteed to
** operate consistently from one release to the next.
*/
SQLCIPHER_API int sqlcipher3_test_control(int op, ...);

/*
** CAPI3REF: Testing Interface Operation Codes
**
** These constants are the valid operation code parameters used
** as the first argument to [sqlcipher3_test_control()].
**
** These parameters and their meanings are subject to change
** without notice.  These values are for testing purposes only.
** Applications should not use any of these parameters or the
** [sqlcipher3_test_control()] interface.
*/
#define SQLCIPHER_TESTCTRL_FIRST                    5
#define SQLCIPHER_TESTCTRL_PRNG_SAVE                5
#define SQLCIPHER_TESTCTRL_PRNG_RESTORE             6
#define SQLCIPHER_TESTCTRL_PRNG_RESET               7
#define SQLCIPHER_TESTCTRL_BITVEC_TEST              8
#define SQLCIPHER_TESTCTRL_FAULT_INSTALL            9
#define SQLCIPHER_TESTCTRL_BENIGN_MALLOC_HOOKS     10
#define SQLCIPHER_TESTCTRL_PENDING_BYTE            11
#define SQLCIPHER_TESTCTRL_ASSERT                  12
#define SQLCIPHER_TESTCTRL_ALWAYS                  13
#define SQLCIPHER_TESTCTRL_RESERVE                 14
#define SQLCIPHER_TESTCTRL_OPTIMIZATIONS           15
#define SQLCIPHER_TESTCTRL_ISKEYWORD               16
#define SQLCIPHER_TESTCTRL_PGHDRSZ                 17
#define SQLCIPHER_TESTCTRL_SCRATCHMALLOC           18
#define SQLCIPHER_TESTCTRL_LOCALTIME_FAULT         19
#define SQLCIPHER_TESTCTRL_LAST                    19

/*
** CAPI3REF: SQLite Runtime Status
**
** ^This interface is used to retrieve runtime status information
** about the performance of SQLite, and optionally to reset various
** highwater marks.  ^The first argument is an integer code for
** the specific parameter to measure.  ^(Recognized integer codes
** are of the form [status parameters | SQLCIPHER_STATUS_...].)^
** ^The current value of the parameter is returned into *pCurrent.
** ^The highest recorded value is returned in *pHighwater.  ^If the
** resetFlag is true, then the highest record value is reset after
** *pHighwater is written.  ^(Some parameters do not record the highest
** value.  For those parameters
** nothing is written into *pHighwater and the resetFlag is ignored.)^
** ^(Other parameters record only the highwater mark and not the current
** value.  For these latter parameters nothing is written into *pCurrent.)^
**
** ^The sqlcipher3_status() routine returns SQLCIPHER_OK on success and a
** non-zero [error code] on failure.
**
** This routine is threadsafe but is not atomic.  This routine can be
** called while other threads are running the same or different SQLite
** interfaces.  However the values returned in *pCurrent and
** *pHighwater reflect the status of SQLite at different points in time
** and it is possible that another thread might change the parameter
** in between the times when *pCurrent and *pHighwater are written.
**
** See also: [sqlcipher3_db_status()]
*/
SQLCIPHER_API int sqlcipher3_status(int op, int *pCurrent, int *pHighwater, int resetFlag);


/*
** CAPI3REF: Status Parameters
** KEYWORDS: {status parameters}
**
** These integer constants designate various run-time status parameters
** that can be returned by [sqlcipher3_status()].
**
** <dl>
** [[SQLCIPHER_STATUS_MEMORY_USED]] ^(<dt>SQLCIPHER_STATUS_MEMORY_USED</dt>
** <dd>This parameter is the current amount of memory checked out
** using [sqlcipher3_malloc()], either directly or indirectly.  The
** figure includes calls made to [sqlcipher3_malloc()] by the application
** and internal memory usage by the SQLite library.  Scratch memory
** controlled by [SQLCIPHER_CONFIG_SCRATCH] and auxiliary page-cache
** memory controlled by [SQLCIPHER_CONFIG_PAGECACHE] is not included in
** this parameter.  The amount returned is the sum of the allocation
** sizes as reported by the xSize method in [sqlcipher3_mem_methods].</dd>)^
**
** [[SQLCIPHER_STATUS_MALLOC_SIZE]] ^(<dt>SQLCIPHER_STATUS_MALLOC_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [sqlcipher3_malloc()] or [sqlcipher3_realloc()] (or their
** internal equivalents).  Only the value returned in the
** *pHighwater parameter to [sqlcipher3_status()] is of interest.  
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLCIPHER_STATUS_MALLOC_COUNT]] ^(<dt>SQLCIPHER_STATUS_MALLOC_COUNT</dt>
** <dd>This parameter records the number of separate memory allocations
** currently checked out.</dd>)^
**
** [[SQLCIPHER_STATUS_PAGECACHE_USED]] ^(<dt>SQLCIPHER_STATUS_PAGECACHE_USED</dt>
** <dd>This parameter returns the number of pages used out of the
** [pagecache memory allocator] that was configured using 
** [SQLCIPHER_CONFIG_PAGECACHE].  The
** value returned is in pages, not in bytes.</dd>)^
**
** [[SQLCIPHER_STATUS_PAGECACHE_OVERFLOW]] 
** ^(<dt>SQLCIPHER_STATUS_PAGECACHE_OVERFLOW</dt>
** <dd>This parameter returns the number of bytes of page cache
** allocation which could not be satisfied by the [SQLCIPHER_CONFIG_PAGECACHE]
** buffer and where forced to overflow to [sqlcipher3_malloc()].  The
** returned value includes allocations that overflowed because they
** where too large (they were larger than the "sz" parameter to
** [SQLCIPHER_CONFIG_PAGECACHE]) and allocations that overflowed because
** no space was left in the page cache.</dd>)^
**
** [[SQLCIPHER_STATUS_PAGECACHE_SIZE]] ^(<dt>SQLCIPHER_STATUS_PAGECACHE_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [pagecache memory allocator].  Only the value returned in the
** *pHighwater parameter to [sqlcipher3_status()] is of interest.  
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLCIPHER_STATUS_SCRATCH_USED]] ^(<dt>SQLCIPHER_STATUS_SCRATCH_USED</dt>
** <dd>This parameter returns the number of allocations used out of the
** [scratch memory allocator] configured using
** [SQLCIPHER_CONFIG_SCRATCH].  The value returned is in allocations, not
** in bytes.  Since a single thread may only have one scratch allocation
** outstanding at time, this parameter also reports the number of threads
** using scratch memory at the same time.</dd>)^
**
** [[SQLCIPHER_STATUS_SCRATCH_OVERFLOW]] ^(<dt>SQLCIPHER_STATUS_SCRATCH_OVERFLOW</dt>
** <dd>This parameter returns the number of bytes of scratch memory
** allocation which could not be satisfied by the [SQLCIPHER_CONFIG_SCRATCH]
** buffer and where forced to overflow to [sqlcipher3_malloc()].  The values
** returned include overflows because the requested allocation was too
** larger (that is, because the requested allocation was larger than the
** "sz" parameter to [SQLCIPHER_CONFIG_SCRATCH]) and because no scratch buffer
** slots were available.
** </dd>)^
**
** [[SQLCIPHER_STATUS_SCRATCH_SIZE]] ^(<dt>SQLCIPHER_STATUS_SCRATCH_SIZE</dt>
** <dd>This parameter records the largest memory allocation request
** handed to [scratch memory allocator].  Only the value returned in the
** *pHighwater parameter to [sqlcipher3_status()] is of interest.  
** The value written into the *pCurrent parameter is undefined.</dd>)^
**
** [[SQLCIPHER_STATUS_PARSER_STACK]] ^(<dt>SQLCIPHER_STATUS_PARSER_STACK</dt>
** <dd>This parameter records the deepest parser stack.  It is only
** meaningful if SQLite is compiled with [YYTRACKMAXSTACKDEPTH].</dd>)^
** </dl>
**
** New status parameters may be added from time to time.
*/
#define SQLCIPHER_STATUS_MEMORY_USED          0
#define SQLCIPHER_STATUS_PAGECACHE_USED       1
#define SQLCIPHER_STATUS_PAGECACHE_OVERFLOW   2
#define SQLCIPHER_STATUS_SCRATCH_USED         3
#define SQLCIPHER_STATUS_SCRATCH_OVERFLOW     4
#define SQLCIPHER_STATUS_MALLOC_SIZE          5
#define SQLCIPHER_STATUS_PARSER_STACK         6
#define SQLCIPHER_STATUS_PAGECACHE_SIZE       7
#define SQLCIPHER_STATUS_SCRATCH_SIZE         8
#define SQLCIPHER_STATUS_MALLOC_COUNT         9

/*
** CAPI3REF: Database Connection Status
**
** ^This interface is used to retrieve runtime status information 
** about a single [database connection].  ^The first argument is the
** database connection object to be interrogated.  ^The second argument
** is an integer constant, taken from the set of
** [SQLCIPHER_DBSTATUS options], that
** determines the parameter to interrogate.  The set of 
** [SQLCIPHER_DBSTATUS options] is likely
** to grow in future releases of SQLite.
**
** ^The current value of the requested parameter is written into *pCur
** and the highest instantaneous value is written into *pHiwtr.  ^If
** the resetFlg is true, then the highest instantaneous value is
** reset back down to the current value.
**
** ^The sqlcipher3_db_status() routine returns SQLCIPHER_OK on success and a
** non-zero [error code] on failure.
**
** See also: [sqlcipher3_status()] and [sqlcipher3_stmt_status()].
*/
SQLCIPHER_API int sqlcipher3_db_status(sqlcipher3*, int op, int *pCur, int *pHiwtr, int resetFlg);

/*
** CAPI3REF: Status Parameters for database connections
** KEYWORDS: {SQLCIPHER_DBSTATUS options}
**
** These constants are the available integer "verbs" that can be passed as
** the second argument to the [sqlcipher3_db_status()] interface.
**
** New verbs may be added in future releases of SQLite. Existing verbs
** might be discontinued. Applications should check the return code from
** [sqlcipher3_db_status()] to make sure that the call worked.
** The [sqlcipher3_db_status()] interface will return a non-zero error code
** if a discontinued or unsupported verb is invoked.
**
** <dl>
** [[SQLCIPHER_DBSTATUS_LOOKASIDE_USED]] ^(<dt>SQLCIPHER_DBSTATUS_LOOKASIDE_USED</dt>
** <dd>This parameter returns the number of lookaside memory slots currently
** checked out.</dd>)^
**
** [[SQLCIPHER_DBSTATUS_LOOKASIDE_HIT]] ^(<dt>SQLCIPHER_DBSTATUS_LOOKASIDE_HIT</dt>
** <dd>This parameter returns the number malloc attempts that were 
** satisfied using lookaside memory. Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_SIZE]]
** ^(<dt>SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_SIZE</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to the amount of
** memory requested being larger than the lookaside slot size.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_FULL]]
** ^(<dt>SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_FULL</dt>
** <dd>This parameter returns the number malloc attempts that might have
** been satisfied using lookaside memory but failed due to all lookaside
** memory already being in use.
** Only the high-water value is meaningful;
** the current value is always zero.)^
**
** [[SQLCIPHER_DBSTATUS_CACHE_USED]] ^(<dt>SQLCIPHER_DBSTATUS_CACHE_USED</dt>
** <dd>This parameter returns the approximate number of of bytes of heap
** memory used by all pager caches associated with the database connection.)^
** ^The highwater mark associated with SQLCIPHER_DBSTATUS_CACHE_USED is always 0.
**
** [[SQLCIPHER_DBSTATUS_SCHEMA_USED]] ^(<dt>SQLCIPHER_DBSTATUS_SCHEMA_USED</dt>
** <dd>This parameter returns the approximate number of of bytes of heap
** memory used to store the schema for all databases associated
** with the connection - main, temp, and any [ATTACH]-ed databases.)^ 
** ^The full amount of memory used by the schemas is reported, even if the
** schema memory is shared with other database connections due to
** [shared cache mode] being enabled.
** ^The highwater mark associated with SQLCIPHER_DBSTATUS_SCHEMA_USED is always 0.
**
** [[SQLCIPHER_DBSTATUS_STMT_USED]] ^(<dt>SQLCIPHER_DBSTATUS_STMT_USED</dt>
** <dd>This parameter returns the approximate number of of bytes of heap
** and lookaside memory used by all prepared statements associated with
** the database connection.)^
** ^The highwater mark associated with SQLCIPHER_DBSTATUS_STMT_USED is always 0.
** </dd>
**
** [[SQLCIPHER_DBSTATUS_CACHE_HIT]] ^(<dt>SQLCIPHER_DBSTATUS_CACHE_HIT</dt>
** <dd>This parameter returns the number of pager cache hits that have
** occurred.)^ ^The highwater mark associated with SQLCIPHER_DBSTATUS_CACHE_HIT 
** is always 0.
** </dd>
**
** [[SQLCIPHER_DBSTATUS_CACHE_MISS]] ^(<dt>SQLCIPHER_DBSTATUS_CACHE_MISS</dt>
** <dd>This parameter returns the number of pager cache misses that have
** occurred.)^ ^The highwater mark associated with SQLCIPHER_DBSTATUS_CACHE_MISS 
** is always 0.
** </dd>
** </dl>
*/
#define SQLCIPHER_DBSTATUS_LOOKASIDE_USED       0
#define SQLCIPHER_DBSTATUS_CACHE_USED           1
#define SQLCIPHER_DBSTATUS_SCHEMA_USED          2
#define SQLCIPHER_DBSTATUS_STMT_USED            3
#define SQLCIPHER_DBSTATUS_LOOKASIDE_HIT        4
#define SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_SIZE  5
#define SQLCIPHER_DBSTATUS_LOOKASIDE_MISS_FULL  6
#define SQLCIPHER_DBSTATUS_CACHE_HIT            7
#define SQLCIPHER_DBSTATUS_CACHE_MISS           8
#define SQLCIPHER_DBSTATUS_MAX                  8   /* Largest defined DBSTATUS */


/*
** CAPI3REF: Prepared Statement Status
**
** ^(Each prepared statement maintains various
** [SQLCIPHER_STMTSTATUS counters] that measure the number
** of times it has performed specific operations.)^  These counters can
** be used to monitor the performance characteristics of the prepared
** statements.  For example, if the number of table steps greatly exceeds
** the number of table searches or result rows, that would tend to indicate
** that the prepared statement is using a full table scan rather than
** an index.  
**
** ^(This interface is used to retrieve and reset counter values from
** a [prepared statement].  The first argument is the prepared statement
** object to be interrogated.  The second argument
** is an integer code for a specific [SQLCIPHER_STMTSTATUS counter]
** to be interrogated.)^
** ^The current value of the requested counter is returned.
** ^If the resetFlg is true, then the counter is reset to zero after this
** interface call returns.
**
** See also: [sqlcipher3_status()] and [sqlcipher3_db_status()].
*/
SQLCIPHER_API int sqlcipher3_stmt_status(sqlcipher3_stmt*, int op,int resetFlg);

/*
** CAPI3REF: Status Parameters for prepared statements
** KEYWORDS: {SQLCIPHER_STMTSTATUS counter} {SQLCIPHER_STMTSTATUS counters}
**
** These preprocessor macros define integer codes that name counter
** values associated with the [sqlcipher3_stmt_status()] interface.
** The meanings of the various counters are as follows:
**
** <dl>
** [[SQLCIPHER_STMTSTATUS_FULLSCAN_STEP]] <dt>SQLCIPHER_STMTSTATUS_FULLSCAN_STEP</dt>
** <dd>^This is the number of times that SQLite has stepped forward in
** a table as part of a full table scan.  Large numbers for this counter
** may indicate opportunities for performance improvement through 
** careful use of indices.</dd>
**
** [[SQLCIPHER_STMTSTATUS_SORT]] <dt>SQLCIPHER_STMTSTATUS_SORT</dt>
** <dd>^This is the number of sort operations that have occurred.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance through careful use of indices.</dd>
**
** [[SQLCIPHER_STMTSTATUS_AUTOINDEX]] <dt>SQLCIPHER_STMTSTATUS_AUTOINDEX</dt>
** <dd>^This is the number of rows inserted into transient indices that
** were created automatically in order to help joins run faster.
** A non-zero value in this counter may indicate an opportunity to
** improvement performance by adding permanent indices that do not
** need to be reinitialized each time the statement is run.</dd>
** </dl>
*/
#define SQLCIPHER_STMTSTATUS_FULLSCAN_STEP     1
#define SQLCIPHER_STMTSTATUS_SORT              2
#define SQLCIPHER_STMTSTATUS_AUTOINDEX         3

/*
** CAPI3REF: Custom Page Cache Object
**
** The sqlcipher3_pcache type is opaque.  It is implemented by
** the pluggable module.  The SQLite core has no knowledge of
** its size or internal structure and never deals with the
** sqlcipher3_pcache object except by holding and passing pointers
** to the object.
**
** See [sqlcipher3_pcache_methods] for additional information.
*/
typedef struct sqlcipher3_pcache sqlcipher3_pcache;

/*
** CAPI3REF: Application Defined Page Cache.
** KEYWORDS: {page cache}
**
** ^(The [sqlcipher3_config]([SQLCIPHER_CONFIG_PCACHE], ...) interface can
** register an alternative page cache implementation by passing in an 
** instance of the sqlcipher3_pcache_methods structure.)^
** In many applications, most of the heap memory allocated by 
** SQLite is used for the page cache.
** By implementing a 
** custom page cache using this API, an application can better control
** the amount of memory consumed by SQLite, the way in which 
** that memory is allocated and released, and the policies used to 
** determine exactly which parts of a database file are cached and for 
** how long.
**
** The alternative page cache mechanism is an
** extreme measure that is only needed by the most demanding applications.
** The built-in page cache is recommended for most uses.
**
** ^(The contents of the sqlcipher3_pcache_methods structure are copied to an
** internal buffer by SQLite within the call to [sqlcipher3_config].  Hence
** the application may discard the parameter after the call to
** [sqlcipher3_config()] returns.)^
**
** [[the xInit() page cache method]]
** ^(The xInit() method is called once for each effective 
** call to [sqlcipher3_initialize()])^
** (usually only once during the lifetime of the process). ^(The xInit()
** method is passed a copy of the sqlcipher3_pcache_methods.pArg value.)^
** The intent of the xInit() method is to set up global data structures 
** required by the custom page cache implementation. 
** ^(If the xInit() method is NULL, then the 
** built-in default page cache is used instead of the application defined
** page cache.)^
**
** [[the xShutdown() page cache method]]
** ^The xShutdown() method is called by [sqlcipher3_shutdown()].
** It can be used to clean up 
** any outstanding resources before process shutdown, if required.
** ^The xShutdown() method may be NULL.
**
** ^SQLite automatically serializes calls to the xInit method,
** so the xInit method need not be threadsafe.  ^The
** xShutdown method is only called from [sqlcipher3_shutdown()] so it does
** not need to be threadsafe either.  All other methods must be threadsafe
** in multithreaded applications.
**
** ^SQLite will never invoke xInit() more than once without an intervening
** call to xShutdown().
**
** [[the xCreate() page cache methods]]
** ^SQLite invokes the xCreate() method to construct a new cache instance.
** SQLite will typically create one cache instance for each open database file,
** though this is not guaranteed. ^The
** first parameter, szPage, is the size in bytes of the pages that must
** be allocated by the cache.  ^szPage will not be a power of two.  ^szPage
** will the page size of the database file that is to be cached plus an
** increment (here called "R") of less than 250.  SQLite will use the
** extra R bytes on each page to store metadata about the underlying
** database page on disk.  The value of R depends
** on the SQLite version, the target platform, and how SQLite was compiled.
** ^(R is constant for a particular build of SQLite. Except, there are two
** distinct values of R when SQLite is compiled with the proprietary
** ZIPVFS extension.)^  ^The second argument to
** xCreate(), bPurgeable, is true if the cache being created will
** be used to cache database pages of a file stored on disk, or
** false if it is used for an in-memory database. The cache implementation
** does not have to do anything special based with the value of bPurgeable;
** it is purely advisory.  ^On a cache where bPurgeable is false, SQLite will
** never invoke xUnpin() except to deliberately delete a page.
** ^In other words, calls to xUnpin() on a cache with bPurgeable set to
** false will always have the "discard" flag set to true.  
** ^Hence, a cache created with bPurgeable false will
** never contain any unpinned pages.
**
** [[the xCachesize() page cache method]]
** ^(The xCachesize() method may be called at any time by SQLite to set the
** suggested maximum cache-size (number of pages stored by) the cache
** instance passed as the first argument. This is the value configured using
** the SQLite "[PRAGMA cache_size]" command.)^  As with the bPurgeable
** parameter, the implementation is not required to do anything with this
** value; it is advisory only.
**
** [[the xPagecount() page cache methods]]
** The xPagecount() method must return the number of pages currently
** stored in the cache, both pinned and unpinned.
** 
** [[the xFetch() page cache methods]]
** The xFetch() method locates a page in the cache and returns a pointer to 
** the page, or a NULL pointer.
** A "page", in this context, means a buffer of szPage bytes aligned at an
** 8-byte boundary. The page to be fetched is determined by the key. ^The
** minimum key value is 1.  After it has been retrieved using xFetch, the page 
** is considered to be "pinned".
**
** If the requested page is already in the page cache, then the page cache
** implementation must return a pointer to the page buffer with its content
** intact.  If the requested page is not already in the cache, then the
** cache implementation should use the value of the createFlag
** parameter to help it determined what action to take:
**
** <table border=1 width=85% align=center>
** <tr><th> createFlag <th> Behaviour when page is not already in cache
** <tr><td> 0 <td> Do not allocate a new page.  Return NULL.
** <tr><td> 1 <td> Allocate a new page if it easy and convenient to do so.
**                 Otherwise return NULL.
** <tr><td> 2 <td> Make every effort to allocate a new page.  Only return
**                 NULL if allocating a new page is effectively impossible.
** </table>
**
** ^(SQLite will normally invoke xFetch() with a createFlag of 0 or 1.  SQLite
** will only use a createFlag of 2 after a prior call with a createFlag of 1
** failed.)^  In between the to xFetch() calls, SQLite may
** attempt to unpin one or more cache pages by spilling the content of
** pinned pages to disk and synching the operating system disk cache.
**
** [[the xUnpin() page cache method]]
** ^xUnpin() is called by SQLite with a pointer to a currently pinned page
** as its second argument.  If the third parameter, discard, is non-zero,
** then the page must be evicted from the cache.
** ^If the discard parameter is
** zero, then the page may be discarded or retained at the discretion of
** page cache implementation. ^The page cache implementation
** may choose to evict unpinned pages at any time.
**
** The cache must not perform any reference counting. A single 
** call to xUnpin() unpins the page regardless of the number of prior calls 
** to xFetch().
**
** [[the xRekey() page cache methods]]
** The xRekey() method is used to change the key value associated with the
** page passed as the second argument. If the cache
** previously contains an entry associated with newKey, it must be
** discarded. ^Any prior cache entry associated with newKey is guaranteed not
** to be pinned.
**
** When SQLite calls the xTruncate() method, the cache must discard all
** existing cache entries with page numbers (keys) greater than or equal
** to the value of the iLimit parameter passed to xTruncate(). If any
** of these pages are pinned, they are implicitly unpinned, meaning that
** they can be safely discarded.
**
** [[the xDestroy() page cache method]]
** ^The xDestroy() method is used to delete a cache allocated by xCreate().
** All resources associated with the specified cache should be freed. ^After
** calling the xDestroy() method, SQLite considers the [sqlcipher3_pcache*]
** handle invalid, and will not use it with any other sqlcipher3_pcache_methods
** functions.
*/
typedef struct sqlcipher3_pcache_methods sqlcipher3_pcache_methods;
struct sqlcipher3_pcache_methods {
  void *pArg;
  int (*xInit)(void*);
  void (*xShutdown)(void*);
  sqlcipher3_pcache *(*xCreate)(int szPage, int bPurgeable);
  void (*xCachesize)(sqlcipher3_pcache*, int nCachesize);
  int (*xPagecount)(sqlcipher3_pcache*);
  void *(*xFetch)(sqlcipher3_pcache*, unsigned key, int createFlag);
  void (*xUnpin)(sqlcipher3_pcache*, void*, int discard);
  void (*xRekey)(sqlcipher3_pcache*, void*, unsigned oldKey, unsigned newKey);
  void (*xTruncate)(sqlcipher3_pcache*, unsigned iLimit);
  void (*xDestroy)(sqlcipher3_pcache*);
};

/*
** CAPI3REF: Online Backup Object
**
** The sqlcipher3_backup object records state information about an ongoing
** online backup operation.  ^The sqlcipher3_backup object is created by
** a call to [sqlcipher3_backup_init()] and is destroyed by a call to
** [sqlcipher3_backup_finish()].
**
** See Also: [Using the SQLite Online Backup API]
*/
typedef struct sqlcipher3_backup sqlcipher3_backup;

/*
** CAPI3REF: Online Backup API.
**
** The backup API copies the content of one database into another.
** It is useful either for creating backups of databases or
** for copying in-memory databases to or from persistent files. 
**
** See Also: [Using the SQLite Online Backup API]
**
** ^SQLite holds a write transaction open on the destination database file
** for the duration of the backup operation.
** ^The source database is read-locked only while it is being read;
** it is not locked continuously for the entire backup operation.
** ^Thus, the backup may be performed on a live source database without
** preventing other database connections from
** reading or writing to the source database while the backup is underway.
** 
** ^(To perform a backup operation: 
**   <ol>
**     <li><b>sqlcipher3_backup_init()</b> is called once to initialize the
**         backup, 
**     <li><b>sqlcipher3_backup_step()</b> is called one or more times to transfer 
**         the data between the two databases, and finally
**     <li><b>sqlcipher3_backup_finish()</b> is called to release all resources 
**         associated with the backup operation. 
**   </ol>)^
** There should be exactly one call to sqlcipher3_backup_finish() for each
** successful call to sqlcipher3_backup_init().
**
** [[sqlcipher3_backup_init()]] <b>sqlcipher3_backup_init()</b>
**
** ^The D and N arguments to sqlcipher3_backup_init(D,N,S,M) are the 
** [database connection] associated with the destination database 
** and the database name, respectively.
** ^The database name is "main" for the main database, "temp" for the
** temporary database, or the name specified after the AS keyword in
** an [ATTACH] statement for an attached database.
** ^The S and M arguments passed to 
** sqlcipher3_backup_init(D,N,S,M) identify the [database connection]
** and database name of the source database, respectively.
** ^The source and destination [database connections] (parameters S and D)
** must be different or else sqlcipher3_backup_init(D,N,S,M) will fail with
** an error.
**
** ^If an error occurs within sqlcipher3_backup_init(D,N,S,M), then NULL is
** returned and an error code and error message are stored in the
** destination [database connection] D.
** ^The error code and message for the failed call to sqlcipher3_backup_init()
** can be retrieved using the [sqlcipher3_errcode()], [sqlcipher3_errmsg()], and/or
** [sqlcipher3_errmsg16()] functions.
** ^A successful call to sqlcipher3_backup_init() returns a pointer to an
** [sqlcipher3_backup] object.
** ^The [sqlcipher3_backup] object may be used with the sqlcipher3_backup_step() and
** sqlcipher3_backup_finish() functions to perform the specified backup 
** operation.
**
** [[sqlcipher3_backup_step()]] <b>sqlcipher3_backup_step()</b>
**
** ^Function sqlcipher3_backup_step(B,N) will copy up to N pages between 
** the source and destination databases specified by [sqlcipher3_backup] object B.
** ^If N is negative, all remaining source pages are copied. 
** ^If sqlcipher3_backup_step(B,N) successfully copies N pages and there
** are still more pages to be copied, then the function returns [SQLCIPHER_OK].
** ^If sqlcipher3_backup_step(B,N) successfully finishes copying all pages
** from source to destination, then it returns [SQLCIPHER_DONE].
** ^If an error occurs while running sqlcipher3_backup_step(B,N),
** then an [error code] is returned. ^As well as [SQLCIPHER_OK] and
** [SQLCIPHER_DONE], a call to sqlcipher3_backup_step() may return [SQLCIPHER_READONLY],
** [SQLCIPHER_NOMEM], [SQLCIPHER_BUSY], [SQLCIPHER_LOCKED], or an
** [SQLCIPHER_IOERR_ACCESS | SQLCIPHER_IOERR_XXX] extended error code.
**
** ^(The sqlcipher3_backup_step() might return [SQLCIPHER_READONLY] if
** <ol>
** <li> the destination database was opened read-only, or
** <li> the destination database is using write-ahead-log journaling
** and the destination and source page sizes differ, or
** <li> the destination database is an in-memory database and the
** destination and source page sizes differ.
** </ol>)^
**
** ^If sqlcipher3_backup_step() cannot obtain a required file-system lock, then
** the [sqlcipher3_busy_handler | busy-handler function]
** is invoked (if one is specified). ^If the 
** busy-handler returns non-zero before the lock is available, then 
** [SQLCIPHER_BUSY] is returned to the caller. ^In this case the call to
** sqlcipher3_backup_step() can be retried later. ^If the source
** [database connection]
** is being used to write to the source database when sqlcipher3_backup_step()
** is called, then [SQLCIPHER_LOCKED] is returned immediately. ^Again, in this
** case the call to sqlcipher3_backup_step() can be retried later on. ^(If
** [SQLCIPHER_IOERR_ACCESS | SQLCIPHER_IOERR_XXX], [SQLCIPHER_NOMEM], or
** [SQLCIPHER_READONLY] is returned, then 
** there is no point in retrying the call to sqlcipher3_backup_step(). These 
** errors are considered fatal.)^  The application must accept 
** that the backup operation has failed and pass the backup operation handle 
** to the sqlcipher3_backup_finish() to release associated resources.
**
** ^The first call to sqlcipher3_backup_step() obtains an exclusive lock
** on the destination file. ^The exclusive lock is not released until either 
** sqlcipher3_backup_finish() is called or the backup operation is complete 
** and sqlcipher3_backup_step() returns [SQLCIPHER_DONE].  ^Every call to
** sqlcipher3_backup_step() obtains a [shared lock] on the source database that
** lasts for the duration of the sqlcipher3_backup_step() call.
** ^Because the source database is not locked between calls to
** sqlcipher3_backup_step(), the source database may be modified mid-way
** through the backup process.  ^If the source database is modified by an
** external process or via a database connection other than the one being
** used by the backup operation, then the backup will be automatically
** restarted by the next call to sqlcipher3_backup_step(). ^If the source 
** database is modified by the using the same database connection as is used
** by the backup operation, then the backup database is automatically
** updated at the same time.
**
** [[sqlcipher3_backup_finish()]] <b>sqlcipher3_backup_finish()</b>
**
** When sqlcipher3_backup_step() has returned [SQLCIPHER_DONE], or when the 
** application wishes to abandon the backup operation, the application
** should destroy the [sqlcipher3_backup] by passing it to sqlcipher3_backup_finish().
** ^The sqlcipher3_backup_finish() interfaces releases all
** resources associated with the [sqlcipher3_backup] object. 
** ^If sqlcipher3_backup_step() has not yet returned [SQLCIPHER_DONE], then any
** active write-transaction on the destination database is rolled back.
** The [sqlcipher3_backup] object is invalid
** and may not be used following a call to sqlcipher3_backup_finish().
**
** ^The value returned by sqlcipher3_backup_finish is [SQLCIPHER_OK] if no
** sqlcipher3_backup_step() errors occurred, regardless or whether or not
** sqlcipher3_backup_step() completed.
** ^If an out-of-memory condition or IO error occurred during any prior
** sqlcipher3_backup_step() call on the same [sqlcipher3_backup] object, then
** sqlcipher3_backup_finish() returns the corresponding [error code].
**
** ^A return of [SQLCIPHER_BUSY] or [SQLCIPHER_LOCKED] from sqlcipher3_backup_step()
** is not a permanent error and does not affect the return value of
** sqlcipher3_backup_finish().
**
** [[sqlcipher3_backup__remaining()]] [[sqlcipher3_backup_pagecount()]]
** <b>sqlcipher3_backup_remaining() and sqlcipher3_backup_pagecount()</b>
**
** ^Each call to sqlcipher3_backup_step() sets two values inside
** the [sqlcipher3_backup] object: the number of pages still to be backed
** up and the total number of pages in the source database file.
** The sqlcipher3_backup_remaining() and sqlcipher3_backup_pagecount() interfaces
** retrieve these two values, respectively.
**
** ^The values returned by these functions are only updated by
** sqlcipher3_backup_step(). ^If the source database is modified during a backup
** operation, then the values are not updated to account for any extra
** pages that need to be updated or the size of the source database file
** changing.
**
** <b>Concurrent Usage of Database Handles</b>
**
** ^The source [database connection] may be used by the application for other
** purposes while a backup operation is underway or being initialized.
** ^If SQLite is compiled and configured to support threadsafe database
** connections, then the source database connection may be used concurrently
** from within other threads.
**
** However, the application must guarantee that the destination 
** [database connection] is not passed to any other API (by any thread) after 
** sqlcipher3_backup_init() is called and before the corresponding call to
** sqlcipher3_backup_finish().  SQLite does not currently check to see
** if the application incorrectly accesses the destination [database connection]
** and so no error code is reported, but the operations may malfunction
** nevertheless.  Use of the destination database connection while a
** backup is in progress might also also cause a mutex deadlock.
**
** If running in [shared cache mode], the application must
** guarantee that the shared cache used by the destination database
** is not accessed while the backup is running. In practice this means
** that the application must guarantee that the disk file being 
** backed up to is not accessed by any connection within the process,
** not just the specific connection that was passed to sqlcipher3_backup_init().
**
** The [sqlcipher3_backup] object itself is partially threadsafe. Multiple 
** threads may safely make multiple concurrent calls to sqlcipher3_backup_step().
** However, the sqlcipher3_backup_remaining() and sqlcipher3_backup_pagecount()
** APIs are not strictly speaking threadsafe. If they are invoked at the
** same time as another thread is invoking sqlcipher3_backup_step() it is
** possible that they return invalid values.
*/
SQLCIPHER_API sqlcipher3_backup *sqlcipher3_backup_init(
  sqlcipher3 *pDest,                        /* Destination database handle */
  const char *zDestName,                 /* Destination database name */
  sqlcipher3 *pSource,                      /* Source database handle */
  const char *zSourceName                /* Source database name */
);
SQLCIPHER_API int sqlcipher3_backup_step(sqlcipher3_backup *p, int nPage);
SQLCIPHER_API int sqlcipher3_backup_finish(sqlcipher3_backup *p);
SQLCIPHER_API int sqlcipher3_backup_remaining(sqlcipher3_backup *p);
SQLCIPHER_API int sqlcipher3_backup_pagecount(sqlcipher3_backup *p);

/*
** CAPI3REF: Unlock Notification
**
** ^When running in shared-cache mode, a database operation may fail with
** an [SQLCIPHER_LOCKED] error if the required locks on the shared-cache or
** individual tables within the shared-cache cannot be obtained. See
** [SQLite Shared-Cache Mode] for a description of shared-cache locking. 
** ^This API may be used to register a callback that SQLite will invoke 
** when the connection currently holding the required lock relinquishes it.
** ^This API is only available if the library was compiled with the
** [SQLCIPHER_ENABLE_UNLOCK_NOTIFY] C-preprocessor symbol defined.
**
** See Also: [Using the SQLite Unlock Notification Feature].
**
** ^Shared-cache locks are released when a database connection concludes
** its current transaction, either by committing it or rolling it back. 
**
** ^When a connection (known as the blocked connection) fails to obtain a
** shared-cache lock and SQLCIPHER_LOCKED is returned to the caller, the
** identity of the database connection (the blocking connection) that
** has locked the required resource is stored internally. ^After an 
** application receives an SQLCIPHER_LOCKED error, it may call the
** sqlcipher3_unlock_notify() method with the blocked connection handle as 
** the first argument to register for a callback that will be invoked
** when the blocking connections current transaction is concluded. ^The
** callback is invoked from within the [sqlcipher3_step] or [sqlcipher3_close]
** call that concludes the blocking connections transaction.
**
** ^(If sqlcipher3_unlock_notify() is called in a multi-threaded application,
** there is a chance that the blocking connection will have already
** concluded its transaction by the time sqlcipher3_unlock_notify() is invoked.
** If this happens, then the specified callback is invoked immediately,
** from within the call to sqlcipher3_unlock_notify().)^
**
** ^If the blocked connection is attempting to obtain a write-lock on a
** shared-cache table, and more than one other connection currently holds
** a read-lock on the same table, then SQLite arbitrarily selects one of 
** the other connections to use as the blocking connection.
**
** ^(There may be at most one unlock-notify callback registered by a 
** blocked connection. If sqlcipher3_unlock_notify() is called when the
** blocked connection already has a registered unlock-notify callback,
** then the new callback replaces the old.)^ ^If sqlcipher3_unlock_notify() is
** called with a NULL pointer as its second argument, then any existing
** unlock-notify callback is canceled. ^The blocked connections 
** unlock-notify callback may also be canceled by closing the blocked
** connection using [sqlcipher3_close()].
**
** The unlock-notify callback is not reentrant. If an application invokes
** any sqlcipher3_xxx API functions from within an unlock-notify callback, a
** crash or deadlock may be the result.
**
** ^Unless deadlock is detected (see below), sqlcipher3_unlock_notify() always
** returns SQLCIPHER_OK.
**
** <b>Callback Invocation Details</b>
**
** When an unlock-notify callback is registered, the application provides a 
** single void* pointer that is passed to the callback when it is invoked.
** However, the signature of the callback function allows SQLite to pass
** it an array of void* context pointers. The first argument passed to
** an unlock-notify callback is a pointer to an array of void* pointers,
** and the second is the number of entries in the array.
**
** When a blocking connections transaction is concluded, there may be
** more than one blocked connection that has registered for an unlock-notify
** callback. ^If two or more such blocked connections have specified the
** same callback function, then instead of invoking the callback function
** multiple times, it is invoked once with the set of void* context pointers
** specified by the blocked connections bundled together into an array.
** This gives the application an opportunity to prioritize any actions 
** related to the set of unblocked database connections.
**
** <b>Deadlock Detection</b>
**
** Assuming that after registering for an unlock-notify callback a 
** database waits for the callback to be issued before taking any further
** action (a reasonable assumption), then using this API may cause the
** application to deadlock. For example, if connection X is waiting for
** connection Y's transaction to be concluded, and similarly connection
** Y is waiting on connection X's transaction, then neither connection
** will proceed and the system may remain deadlocked indefinitely.
**
** To avoid this scenario, the sqlcipher3_unlock_notify() performs deadlock
** detection. ^If a given call to sqlcipher3_unlock_notify() would put the
** system in a deadlocked state, then SQLCIPHER_LOCKED is returned and no
** unlock-notify callback is registered. The system is said to be in
** a deadlocked state if connection A has registered for an unlock-notify
** callback on the conclusion of connection B's transaction, and connection
** B has itself registered for an unlock-notify callback when connection
** A's transaction is concluded. ^Indirect deadlock is also detected, so
** the system is also considered to be deadlocked if connection B has
** registered for an unlock-notify callback on the conclusion of connection
** C's transaction, where connection C is waiting on connection A. ^Any
** number of levels of indirection are allowed.
**
** <b>The "DROP TABLE" Exception</b>
**
** When a call to [sqlcipher3_step()] returns SQLCIPHER_LOCKED, it is almost 
** always appropriate to call sqlcipher3_unlock_notify(). There is however,
** one exception. When executing a "DROP TABLE" or "DROP INDEX" statement,
** SQLite checks if there are any currently executing SELECT statements
** that belong to the same connection. If there are, SQLCIPHER_LOCKED is
** returned. In this case there is no "blocking connection", so invoking
** sqlcipher3_unlock_notify() results in the unlock-notify callback being
** invoked immediately. If the application then re-attempts the "DROP TABLE"
** or "DROP INDEX" query, an infinite loop might be the result.
**
** One way around this problem is to check the extended error code returned
** by an sqlcipher3_step() call. ^(If there is a blocking connection, then the
** extended error code is set to SQLCIPHER_LOCKED_SHAREDCACHE. Otherwise, in
** the special "DROP TABLE/INDEX" case, the extended error code is just 
** SQLCIPHER_LOCKED.)^
*/
SQLCIPHER_API int sqlcipher3_unlock_notify(
  sqlcipher3 *pBlocked,                          /* Waiting connection */
  void (*xNotify)(void **apArg, int nArg),    /* Callback function to invoke */
  void *pNotifyArg                            /* Argument to pass to xNotify */
);


/*
** CAPI3REF: String Comparison
**
** ^The [sqlcipher3_strnicmp()] API allows applications and extensions to
** compare the contents of two buffers containing UTF-8 strings in a
** case-independent fashion, using the same definition of case independence 
** that SQLite uses internally when comparing identifiers.
*/
SQLCIPHER_API int sqlcipher3_strnicmp(const char *, const char *, int);

/*
** CAPI3REF: Error Logging Interface
**
** ^The [sqlcipher3_log()] interface writes a message into the error log
** established by the [SQLCIPHER_CONFIG_LOG] option to [sqlcipher3_config()].
** ^If logging is enabled, the zFormat string and subsequent arguments are
** used with [sqlcipher3_snprintf()] to generate the final output string.
**
** The sqlcipher3_log() interface is intended for use by extensions such as
** virtual tables, collating functions, and SQL functions.  While there is
** nothing to prevent an application from calling sqlcipher3_log(), doing so
** is considered bad form.
**
** The zFormat string must not be NULL.
**
** To avoid deadlocks and other threading problems, the sqlcipher3_log() routine
** will not use dynamically allocated memory.  The log message is stored in
** a fixed-length buffer on the stack.  If the log message is longer than
** a few hundred characters, it will be truncated to the length of the
** buffer.
*/
SQLCIPHER_API void sqlcipher3_log(int iErrCode, const char *zFormat, ...);

/*
** CAPI3REF: Write-Ahead Log Commit Hook
**
** ^The [sqlcipher3_wal_hook()] function is used to register a callback that
** will be invoked each time a database connection commits data to a
** [write-ahead log] (i.e. whenever a transaction is committed in
** [journal_mode | journal_mode=WAL mode]). 
**
** ^The callback is invoked by SQLite after the commit has taken place and 
** the associated write-lock on the database released, so the implementation 
** may read, write or [checkpoint] the database as required.
**
** ^The first parameter passed to the callback function when it is invoked
** is a copy of the third parameter passed to sqlcipher3_wal_hook() when
** registering the callback. ^The second is a copy of the database handle.
** ^The third parameter is the name of the database that was written to -
** either "main" or the name of an [ATTACH]-ed database. ^The fourth parameter
** is the number of pages currently in the write-ahead log file,
** including those that were just committed.
**
** The callback function should normally return [SQLCIPHER_OK].  ^If an error
** code is returned, that error will propagate back up through the
** SQLite code base to cause the statement that provoked the callback
** to report an error, though the commit will have still occurred. If the
** callback returns [SQLCIPHER_ROW] or [SQLCIPHER_DONE], or if it returns a value
** that does not correspond to any valid SQLite error code, the results
** are undefined.
**
** A single database handle may have at most a single write-ahead log callback 
** registered at one time. ^Calling [sqlcipher3_wal_hook()] replaces any
** previously registered write-ahead log callback. ^Note that the
** [sqlcipher3_wal_autocheckpoint()] interface and the
** [wal_autocheckpoint pragma] both invoke [sqlcipher3_wal_hook()] and will
** those overwrite any prior [sqlcipher3_wal_hook()] settings.
*/
SQLCIPHER_API void *sqlcipher3_wal_hook(
  sqlcipher3*, 
  int(*)(void *,sqlcipher3*,const char*,int),
  void*
);

/*
** CAPI3REF: Configure an auto-checkpoint
**
** ^The [sqlcipher3_wal_autocheckpoint(D,N)] is a wrapper around
** [sqlcipher3_wal_hook()] that causes any database on [database connection] D
** to automatically [checkpoint]
** after committing a transaction if there are N or
** more frames in the [write-ahead log] file.  ^Passing zero or 
** a negative value as the nFrame parameter disables automatic
** checkpoints entirely.
**
** ^The callback registered by this function replaces any existing callback
** registered using [sqlcipher3_wal_hook()].  ^Likewise, registering a callback
** using [sqlcipher3_wal_hook()] disables the automatic checkpoint mechanism
** configured by this function.
**
** ^The [wal_autocheckpoint pragma] can be used to invoke this interface
** from SQL.
**
** ^Every new [database connection] defaults to having the auto-checkpoint
** enabled with a threshold of 1000 or [SQLCIPHER_DEFAULT_WAL_AUTOCHECKPOINT]
** pages.  The use of this interface
** is only necessary if the default setting is found to be suboptimal
** for a particular application.
*/
SQLCIPHER_API int sqlcipher3_wal_autocheckpoint(sqlcipher3 *db, int N);

/*
** CAPI3REF: Checkpoint a database
**
** ^The [sqlcipher3_wal_checkpoint(D,X)] interface causes database named X
** on [database connection] D to be [checkpointed].  ^If X is NULL or an
** empty string, then a checkpoint is run on all databases of
** connection D.  ^If the database connection D is not in
** [WAL | write-ahead log mode] then this interface is a harmless no-op.
**
** ^The [wal_checkpoint pragma] can be used to invoke this interface
** from SQL.  ^The [sqlcipher3_wal_autocheckpoint()] interface and the
** [wal_autocheckpoint pragma] can be used to cause this interface to be
** run whenever the WAL reaches a certain size threshold.
**
** See also: [sqlcipher3_wal_checkpoint_v2()]
*/
SQLCIPHER_API int sqlcipher3_wal_checkpoint(sqlcipher3 *db, const char *zDb);

/*
** CAPI3REF: Checkpoint a database
**
** Run a checkpoint operation on WAL database zDb attached to database 
** handle db. The specific operation is determined by the value of the 
** eMode parameter:
**
** <dl>
** <dt>SQLCIPHER_CHECKPOINT_PASSIVE<dd>
**   Checkpoint as many frames as possible without waiting for any database 
**   readers or writers to finish. Sync the db file if all frames in the log
**   are checkpointed. This mode is the same as calling 
**   sqlcipher3_wal_checkpoint(). The busy-handler callback is never invoked.
**
** <dt>SQLCIPHER_CHECKPOINT_FULL<dd>
**   This mode blocks (calls the busy-handler callback) until there is no
**   database writer and all readers are reading from the most recent database
**   snapshot. It then checkpoints all frames in the log file and syncs the
**   database file. This call blocks database writers while it is running,
**   but not database readers.
**
** <dt>SQLCIPHER_CHECKPOINT_RESTART<dd>
**   This mode works the same way as SQLCIPHER_CHECKPOINT_FULL, except after 
**   checkpointing the log file it blocks (calls the busy-handler callback)
**   until all readers are reading from the database file only. This ensures 
**   that the next client to write to the database file restarts the log file 
**   from the beginning. This call blocks database writers while it is running,
**   but not database readers.
** </dl>
**
** If pnLog is not NULL, then *pnLog is set to the total number of frames in
** the log file before returning. If pnCkpt is not NULL, then *pnCkpt is set to
** the total number of checkpointed frames (including any that were already
** checkpointed when this function is called). *pnLog and *pnCkpt may be
** populated even if sqlcipher3_wal_checkpoint_v2() returns other than SQLCIPHER_OK.
** If no values are available because of an error, they are both set to -1
** before returning to communicate this to the caller.
**
** All calls obtain an exclusive "checkpoint" lock on the database file. If
** any other process is running a checkpoint operation at the same time, the 
** lock cannot be obtained and SQLCIPHER_BUSY is returned. Even if there is a 
** busy-handler configured, it will not be invoked in this case.
**
** The SQLCIPHER_CHECKPOINT_FULL and RESTART modes also obtain the exclusive 
** "writer" lock on the database file. If the writer lock cannot be obtained
** immediately, and a busy-handler is configured, it is invoked and the writer
** lock retried until either the busy-handler returns 0 or the lock is
** successfully obtained. The busy-handler is also invoked while waiting for
** database readers as described above. If the busy-handler returns 0 before
** the writer lock is obtained or while waiting for database readers, the
** checkpoint operation proceeds from that point in the same way as 
** SQLCIPHER_CHECKPOINT_PASSIVE - checkpointing as many frames as possible 
** without blocking any further. SQLCIPHER_BUSY is returned in this case.
**
** If parameter zDb is NULL or points to a zero length string, then the
** specified operation is attempted on all WAL databases. In this case the
** values written to output parameters *pnLog and *pnCkpt are undefined. If 
** an SQLCIPHER_BUSY error is encountered when processing one or more of the 
** attached WAL databases, the operation is still attempted on any remaining 
** attached databases and SQLCIPHER_BUSY is returned to the caller. If any other 
** error occurs while processing an attached database, processing is abandoned 
** and the error code returned to the caller immediately. If no error 
** (SQLCIPHER_BUSY or otherwise) is encountered while processing the attached 
** databases, SQLCIPHER_OK is returned.
**
** If database zDb is the name of an attached database that is not in WAL
** mode, SQLCIPHER_OK is returned and both *pnLog and *pnCkpt set to -1. If
** zDb is not NULL (or a zero length string) and is not the name of any
** attached database, SQLCIPHER_ERROR is returned to the caller.
*/
SQLCIPHER_API int sqlcipher3_wal_checkpoint_v2(
  sqlcipher3 *db,                    /* Database handle */
  const char *zDb,                /* Name of attached database (or NULL) */
  int eMode,                      /* SQLCIPHER_CHECKPOINT_* value */
  int *pnLog,                     /* OUT: Size of WAL log in frames */
  int *pnCkpt                     /* OUT: Total number of frames checkpointed */
);

/*
** CAPI3REF: Checkpoint operation parameters
**
** These constants can be used as the 3rd parameter to
** [sqlcipher3_wal_checkpoint_v2()].  See the [sqlcipher3_wal_checkpoint_v2()]
** documentation for additional information about the meaning and use of
** each of these values.
*/
#define SQLCIPHER_CHECKPOINT_PASSIVE 0
#define SQLCIPHER_CHECKPOINT_FULL    1
#define SQLCIPHER_CHECKPOINT_RESTART 2

/*
** CAPI3REF: Virtual Table Interface Configuration
**
** This function may be called by either the [xConnect] or [xCreate] method
** of a [virtual table] implementation to configure
** various facets of the virtual table interface.
**
** If this interface is invoked outside the context of an xConnect or
** xCreate virtual table method then the behavior is undefined.
**
** At present, there is only one option that may be configured using
** this function. (See [SQLCIPHER_VTAB_CONSTRAINT_SUPPORT].)  Further options
** may be added in the future.
*/
SQLCIPHER_API int sqlcipher3_vtab_config(sqlcipher3*, int op, ...);

/*
** CAPI3REF: Virtual Table Configuration Options
**
** These macros define the various options to the
** [sqlcipher3_vtab_config()] interface that [virtual table] implementations
** can use to customize and optimize their behavior.
**
** <dl>
** <dt>SQLCIPHER_VTAB_CONSTRAINT_SUPPORT
** <dd>Calls of the form
** [sqlcipher3_vtab_config](db,SQLCIPHER_VTAB_CONSTRAINT_SUPPORT,X) are supported,
** where X is an integer.  If X is zero, then the [virtual table] whose
** [xCreate] or [xConnect] method invoked [sqlcipher3_vtab_config()] does not
** support constraints.  In this configuration (which is the default) if
** a call to the [xUpdate] method returns [SQLCIPHER_CONSTRAINT], then the entire
** statement is rolled back as if [ON CONFLICT | OR ABORT] had been
** specified as part of the users SQL statement, regardless of the actual
** ON CONFLICT mode specified.
**
** If X is non-zero, then the virtual table implementation guarantees
** that if [xUpdate] returns [SQLCIPHER_CONSTRAINT], it will do so before
** any modifications to internal or persistent data structures have been made.
** If the [ON CONFLICT] mode is ABORT, FAIL, IGNORE or ROLLBACK, SQLite 
** is able to roll back a statement or database transaction, and abandon
** or continue processing the current SQL statement as appropriate. 
** If the ON CONFLICT mode is REPLACE and the [xUpdate] method returns
** [SQLCIPHER_CONSTRAINT], SQLite handles this as if the ON CONFLICT mode
** had been ABORT.
**
** Virtual table implementations that are required to handle OR REPLACE
** must do so within the [xUpdate] method. If a call to the 
** [sqlcipher3_vtab_on_conflict()] function indicates that the current ON 
** CONFLICT policy is REPLACE, the virtual table implementation should 
** silently replace the appropriate rows within the xUpdate callback and
** return SQLCIPHER_OK. Or, if this is not possible, it may return
** SQLCIPHER_CONSTRAINT, in which case SQLite falls back to OR ABORT 
** constraint handling.
** </dl>
*/
#define SQLCIPHER_VTAB_CONSTRAINT_SUPPORT 1

/*
** CAPI3REF: Determine The Virtual Table Conflict Policy
**
** This function may only be called from within a call to the [xUpdate] method
** of a [virtual table] implementation for an INSERT or UPDATE operation. ^The
** value returned is one of [SQLCIPHER_ROLLBACK], [SQLCIPHER_IGNORE], [SQLCIPHER_FAIL],
** [SQLCIPHER_ABORT], or [SQLCIPHER_REPLACE], according to the [ON CONFLICT] mode
** of the SQL statement that triggered the call to the [xUpdate] method of the
** [virtual table].
*/
SQLCIPHER_API int sqlcipher3_vtab_on_conflict(sqlcipher3 *);

/*
** CAPI3REF: Conflict resolution modes
**
** These constants are returned by [sqlcipher3_vtab_on_conflict()] to
** inform a [virtual table] implementation what the [ON CONFLICT] mode
** is for the SQL statement being evaluated.
**
** Note that the [SQLCIPHER_IGNORE] constant is also used as a potential
** return value from the [sqlcipher3_set_authorizer()] callback and that
** [SQLCIPHER_ABORT] is also a [result code].
*/
#define SQLCIPHER_ROLLBACK 1
/* #define SQLCIPHER_IGNORE 2 // Also used by sqlcipher3_authorizer() callback */
#define SQLCIPHER_FAIL     3
/* #define SQLCIPHER_ABORT 4  // Also an error code */
#define SQLCIPHER_REPLACE  5



/*
** Undo the hack that converts floating point types to integer for
** builds on processors without floating point support.
*/
#ifdef SQLCIPHER_OMIT_FLOATING_POINT
# undef double
#endif

#ifdef __cplusplus
}  /* End of the 'extern "C"' block */
#endif
#endif

/*
** 2010 August 30
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
*/

#ifndef _SQLCIPHER3RTREE_H_
#define _SQLCIPHER3RTREE_H_


#ifdef __cplusplus
extern "C" {
#endif

typedef struct sqlcipher3_rtree_geometry sqlcipher3_rtree_geometry;

/*
** Register a geometry callback named zGeom that can be used as part of an
** R-Tree geometry query as follows:
**
**   SELECT ... FROM <rtree> WHERE <rtree col> MATCH $zGeom(... params ...)
*/
SQLCIPHER_API int sqlcipher3_rtree_geometry_callback(
  sqlcipher3 *db,
  const char *zGeom,
  int (*xGeom)(sqlcipher3_rtree_geometry *, int nCoord, double *aCoord, int *pRes),
  void *pContext
);


/*
** A pointer to a structure of the following type is passed as the first
** argument to callbacks registered using rtree_geometry_callback().
*/
struct sqlcipher3_rtree_geometry {
  void *pContext;                 /* Copy of pContext passed to s_r_g_c() */
  int nParam;                     /* Size of array aParam[] */
  double *aParam;                 /* Parameters passed to SQL geom function */
  void *pUser;                    /* Callback implementation user data */
  void (*xDelUser)(void *);       /* Called by SQLite to clean up pUser */
};


#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif

#endif  /* ifndef _SQLCIPHER3RTREE_H_ */

