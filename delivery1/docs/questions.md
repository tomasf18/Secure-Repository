Organizations can be universally listed, as well as the public metadata of their documents.
Qualquer pessoa pode ter acesso à metadata dos documentos de uma organização? 

Sim (para ja, mas depois com autenticacao ja nao)

---

All subjects hold one or more key pairs, and their public keys are available in the Repository.
(Ver imagem abaixo, para ver se as public keys armazenadas na tabela "OrgSubj" bastam)

Os key pairs são armazenados localmente?

R.: Sim, e as public keys no repositório

---

Each subject must have a set of well-defined identity attributes in their association profile. We will consider 4:

    username;
    full_name;
    email;
    public_key.


O que é essa "public_key"?

R.: Já a removi

---

All subjects hold one or more key pairs
Privada -> localmente
Publica -> no repositorio


Criámos uma tabela à parte para isso.
Mas com isto, precisamos da public_key no subject?

R.: Não (ver diagrama)


  ---

  Each session must have an identifier and one or more keys
  The session keys must be used to enforce the confidentiality (when necessary) and the integrity (correctness and freshness) of messages exchanged during a session. Different keys can be used for the different protections, if deemed necessary.

 

  -> Confidencialidade: PubK Danilo
  -> Integridade: PrivK Tomás

  R.: VER NOVA FORMA








  ---

  como é que associamos um document a um file sendo que os files estão noutro storage?
  É só guardar o file handle, que irá identificar o ficherio no outro storage, certo?

  R.: Sim

  ---

  A session always implicitly refers to one specific Repository organization.

  Como assim "implicitly"? É suposto termos na tabela session uma foreign key para a tabela org e outra para a tabela subject, certo?

  R.: Sim

  --- 

  When subjects are associated to one organization, they choose an existing or new public key for that context.

  Esta parte é toda feita localmente (do lado do cliente)

  R.: Sim

  ---

 session is created upon a login operation in that organization, performed with the credentials that the organization maintains about the subject. 

 O que é que são estas "**credentials**"?

 R.: 

  ---

  Replay: an attacker cannot be able to replay and interaction that took place within a session. Therefore, the software must be able to detect out of order or past messages.

  R.: nº de sequencia resolve isto (nº é melhor do que timestamp)
  
---

```bash
rep_create_org <organization> <username> <name> <email> <public key file>
```

Para que é que temos a pub_key do subject no repo se temos de passar como ficheiro?

R.: NESTE CASO NÃO EXISTE NENHUMA PUBLIC KEY ASSOCIADA À ORGANIZAÇÃO, ENTÃO TEMOS DE PASSAR

rep_add_subject <session file> <username> <name> <email> <credentials file>

credentials file é só a public key.

<session file> -> Para verificar se o subject que está a adicionar tem permissoes para isso
