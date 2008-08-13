#
# Customized version of Apache2::AuthTicket
#

package KWebTicket;

use strict;
use base 'Apache2::AuthTicket';

use DBI ();

use constant DEBUGGING => 0;

our $VERSION = '0.40';

# AuthTicket->check_credentials is called by AuthTicket->authen_cred,
# which is called by AuthCookie->login, the perl handler
# for the URL that the login form is posted to.
# We override AuthTicket->check_credentials providing a new
# TicketPasswordStyle, 'nocase' for comparing passwords
# case-insensitively.
 
sub check_credentials {
    my ($this, $user, $password) = @_;
    $this->_log_entry if DEBUGGING;

    my $style = $this->{TicketPasswordStyle};
    if ($style ne 'nocase') {
	return $this->SUPER::check_credentials($user, $password);
    }

    my ($table, $user_field, $pass_field) = 
        split(/:/, $this->{TicketUserTable});

    my $dbh = $this->dbh;

    return (undef, "Can't open database: $DBI::errstr") unless $dbh;

    return (undef, "invalid account") unless $this->check_user($user);

    # we might add an option for crypt or MD5 style password someday
    my $saved_passwd = $this->get_password($user);

    # lowercase both passwords before comparing
    my $result = $this->_compare_password_cleartext(lc($password), lc($saved_passwd));
    return (undef, "password mismatch") unless $result;

    # its valid.
    return (1, '');
}
