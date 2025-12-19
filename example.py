def main():
    from automate.eserv import make_email_record
    from tests.eserv.lib import sample_path

    return make_email_record(body=sample_path(mock=False).read_text())
