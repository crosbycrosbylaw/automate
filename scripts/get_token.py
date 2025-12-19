if __name__ == '__main__':
    import fire

    from automate.eserv.monitor.utils import get_token_with_login

    fire.Fire({'authenticate': get_token_with_login}, ['authenticate'])
