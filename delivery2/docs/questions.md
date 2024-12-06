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