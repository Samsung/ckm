#ifndef COLOUR_LOG_FORMATTER_H_
#define COLOUR_LOG_FORMATTER_H_

#include <boost/test/unit_test_log_formatter.hpp>

namespace CKM {
class colour_log_formatter : public boost::unit_test::unit_test_log_formatter {
public:
    // Formatter interface
    colour_log_formatter() : m_isTestCaseFailed(false) {}
    void    log_start(
                std::ostream&,
                boost::unit_test::counter_t test_cases_amount );
    void    log_finish( std::ostream& );
    void    log_build_info( std::ostream& );

    void    test_unit_start(
                std::ostream&,
                boost::unit_test::test_unit const& tu );
    void    test_unit_finish(
                std::ostream&,
                boost::unit_test::test_unit const& tu,
                unsigned long elapsed );
    void    test_unit_skipped(
                std::ostream&,
                boost::unit_test::test_unit const& tu );

    void    log_exception(
                std::ostream&,
                boost::unit_test::log_checkpoint_data const&,
                boost::execution_exception const& ex );

    void    log_entry_start(
                std::ostream&,
                boost::unit_test::log_entry_data const&,
                log_entry_types let );
    void    log_entry_value(
                std::ostream&,
                boost::unit_test::const_string value );
    void    log_entry_value(
                std::ostream&,
                boost::unit_test::lazy_ostream const& value );
    void    log_entry_finish( std::ostream& );
private:
    bool m_isTestCaseFailed;
};
} // namespace CKM

#endif /* COLOUR_LOG_FORMATTER_H_ */
