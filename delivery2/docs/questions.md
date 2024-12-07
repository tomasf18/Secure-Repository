    def add_session_role(self, session_id: int, role: str) -> Role:
        """
        Add a role to a session.
        """
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")
            
            role_object = self.role_dao.get_by_name_and_acl_id(role, session.organization.acl.id)
            
            session.session_roles.append(role_object)
            role_object.subjects.append(session.subject)    # Eu não posso dar append do subject ao role!!! Supostamente roles na sessao sao diferented de roles na organizaçao
                                                            # Esta parte de dar append do subect ao role é suposto ser feita no rep_add_permission
                                                            # E depois, na sessao, o subject assume roles QUE ELE POSSUI na organizaçáo, e nao qualquer um!! (retirar role_object.subjects.remove(session.subject)
                                                            # da função drop_session_role tambem, e fazer a verificação de se o subject está a tentar asuumir um role que lhe é valido na organizacao
            
            self.session.commit()
            
            self.session.refresh(role_object)
            self.session.refresh(session)
            
            return role_object
        except IntegrityError:
            self.session.rollback()
            
# -------------------------------

    def drop_session_role(self, session_id: int, role: str) -> Role:
        """
        Drop a role from a session.
        """
        try:
            session = self.get_by_id(session_id)
            if not session:
                raise ValueError(f"Session with ID '{session_id}' does not exist.")
            
            role_object = self.role_dao.get_by_name_and_acl_id(role, session.organization.acl.id)
            
            session.session_roles.remove(role_object)
            role_object.subjects.remove(session.subject)
            
            self.session.commit()
            
            self.session.refresh(role_object)
            self.session.refresh(session)
            
            return role_object
        except IntegrityError:
            self.session.rollback()

# -------------------------------

Como é que se destinguem os roles de uma organization ACL dos roles de um document ACL? É suposto os roles serem sempre os mesmos, só que quando usamos o comando
`rep_acl_doc <session file> <document name> [+/-] <role> <permission>` podemos adicionar a permissao de documento ao role, e, se o role nao estiver na ACL do documento, ele é adicionado?
Ou é suposto os roles serem diferentes? E quando uso este mesmo comando, se o role nao
existir, crio um.


Bom dia, @jpbarraca. Tenho as seguintes dúvidas:

1. No comando `rep_assume_role <session file> <role>`, o subject, não sendo um Manager, apenas pode assumir Roles na sessão que lhe tenham sido atribuídos naquela organização, por exemplo, com o comando `rep_add_permission <session file> <role> <username>`, que ` change the properties of a role in the organization with which I have currently a session, by adding a subject`, certo? Ou pode assumir qualquer um que exista na organização? SIM `By default, subjects have no default role upon logging in into a session. They need to explicitly ask for a role they are bound to, and can do so for more than one role per session. They can also release a role during the session. The set of roles associated to each session is stored by the Repository, in the context of each active session.`

2. Qual é a diferença entre a ACL de uma organização da ACL de um documento? Existem as seguintes permissões: `"DOC_ACL", "DOC_READ", "DOC_DELETE", "ROLE_ACL", "SUBJECT_NEW", "SUBJECT_DOWN", "SUBJECT_UP", "DOC_NEW", "ROLE_NEW", "ROLE_DOWN", "ROLE_UP", "ROLE_MOD"`. Mas apenas `DOC_ACL`, `DOC_READ` e `DOC_DELETE` se referem a documentos. Posto isto, como é que se destinguem os roles de uma ACL de org dos de uma ACL de doc? 
É suposto os roles de uma ACL de documento serem um subconjunto dos roles que já existem na organização a que esse documento pertence? E, deste modo, usando o comando `rep_acl_doc <session file> <document name> [+/-] <role> <permission>`, se adiciona uma permissão de documento a uma role já existente na organização? Neste caso, se o role não existir, na ACL do documento, 
    é adicionado, bem como, usando o mesmo comando para remover permissões de documentos, se o role ficar sem permissões para documentos, é retirado da ACL do mesmo?