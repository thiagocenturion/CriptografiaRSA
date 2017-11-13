using System;

namespace CriptografiaRSA
{
    class MainClass
    {
        // Constantes
        static string TEXTO_ENTRADA_INVALIDA = "Entrada inválida. Favor digitar uma das opções corretamente.\n";
        static string TEXTO_MAIOR_QUE_128_RETORNA_PRINCIPAL = "Texto digitado incorretamente. A quantidade de caracteres máxima é de 128. O programa está retornando para a página principal.\n";

        public struct Usuario
        {
            // Usuário e senha de acesso
            public string login;
            public string senha;
        }

        // Cria o struct do usuario
        public static Usuario usuarioRoot;

        public static void Main(string[] args)
        {
            bool sair = false;
            int valorDigitado = 0;
            string login = "";
            string senha = "";
            RSACriptUnip criptografer = null;

            // Seta o usuario e senha de administrador
            usuarioRoot.login = "criptografiarsa";
            usuarioRoot.senha = "unip2017";

            // Instancia o objeto de criptografia
            criptografer = new RSACriptUnip();

            while (sair == false)
            {
                // Solicita o usuario e senha
                Console.WriteLine("\n=====================================");
                Console.WriteLine("========== CRIPTOGRAFIA RSA =========");
                Console.WriteLine("=====================================");
                Console.Write("== USUÁRIO: ");
                login = Console.ReadLine();
                Console.Write("== SENHA: ");
                senha = Console.ReadLine();
                Console.WriteLine("=====================================");
                Console.WriteLine("");

                // Verifica se o login e senha digitados existem
                if (ValidaUsuario(login, senha))
                {
                    // Se não validou, refaz o looping
                    sair = true;
                }
            }

            sair = false;

            while (sair == false)
            {
                // Imprime os controles de decisões
                Console.WriteLine("\n=====================================");
                Console.WriteLine("========== ACESSO PERMITIDO =========");
                Console.WriteLine("=====================================");
                Console.WriteLine("= Digite \"1\" para GERAR AS CHAVES   =");
                Console.WriteLine("= Digite \"2\" para CRIPTOGRAFAR      =");
                Console.WriteLine("= Digite \"3\" para DESCRIPTOGRAFAR   =");
                Console.WriteLine("= Digite \"4\" para SAIR              =");
                Console.WriteLine("=====================================");

                // Tenta pegar o valor digitado
                if (int.TryParse(Console.ReadLine(), out valorDigitado) == false)
                {
                    // Caso tenha ocorrido um erro ao tentar converter o valor para inteiro, exibe uma mensagem de erro
                    Console.WriteLine(TEXTO_ENTRADA_INVALIDA);
                    continue;
                }

                // Verifica qual foi a escolha do usuário
                switch (valorDigitado)
                {
                    case 1:
                        // Realiza os comandos para gerar as chaves
                        if (OpcaoGerarChaves(ref criptografer))
                        {
                            // Pergunta para o usuário se deseja continuar
                            sair = MainClass.PerguntaDesejaContinuar(true);
                        }

                        break;

                    case 2:

                        // Realiza os comandos para a criptografia
                        if (MainClass.OpcaoCriptografia(ref criptografer))
                        {
                            // Pergunta para o usuário se deseja continuar
                            sair = MainClass.PerguntaDesejaContinuar(true);
                        }

                        break;

                    case 3:

                        // Realiza os comandos para a criptografia
                        if (MainClass.OpcaoDescriptografia(ref criptografer))
                        {
                            // Pergunta para o usuário se deseja continuar
                            sair = MainClass.PerguntaDesejaContinuar(true);
                        }

                        break;

                    case 4:

                        // Sai do programa
                        sair = true;

                        break;

                    default:

                        Console.WriteLine(TEXTO_ENTRADA_INVALIDA);

                        break;
                }
            }

            Console.Write("Digite qualquer tecla para encerrar.");
            Console.ReadKey();
        }

        public static bool ValidaUsuario(string login, string senha)
        {
            bool usuarioValido = true;

            // Verifica se o login digitado existe (compara com o usuário do admin)
            if (login != usuarioRoot.login)
            {
                // Caso seja usuário inválido, exibe mensagem e retorna a função
                Console.WriteLine("Login inexistente.");
                usuarioValido = false;
            }
            else
            {
                // Verifica se a senha está correta
                if (senha != usuarioRoot.senha)
                {
                    // Caso seja senha inválida, exibe mensagem e retorna a função
                    Console.WriteLine("Senha incorreta.");
                    usuarioValido = false;
                }
            }

            return usuarioValido;
        }

        public static bool OpcaoGerarChaves(ref RSACriptUnip criptografer)
        {
            int p = 0, q = 0, moduloN, totienteN, d;
            bool encontrouPrimos = false;
            Random rdn = new Random();
            string chavePublica = "";
            string chavePrivada = "";

            while (encontrouPrimos == false)
            {
                // Gera um valor aleatorio para P e Q tal que 101 <= p <= 997 e 101 <= q <= 997
                p = rdn.Next(1, 997);
                q = rdn.Next(1000);
                q = rdn.Next(1, 997);

                // Verifica se os números digitados são primos
                if (!VerificaPrimo(p))
                {
                    encontrouPrimos = false;
                }
                else
                {
                    if (!VerificaPrimo(q))
                    {
                        encontrouPrimos = false;
                    }
                    else
                    {
                        encontrouPrimos = true;
                    }
                }
            }

            // Calcula a chave pública N e armazena no objeto
            moduloN = criptografer.CalcularN(p, q);

            // Calcula e retorna o totiente de N
            totienteN = criptografer.CalcularTotienteN(p, q);

            // Calcula a segunda chave púbica E e armazena no objeto
            criptografer.CalcularE(totienteN);

            // Pega a chave pública E(chave que utiliza para CRIPTOGRAFAR)
            chavePublica = criptografer.RetornaChavePublica(criptografer.eValue, moduloN);

            // Imprime para o usuário a chave de criptografia
            Console.WriteLine("\nChave Pública:");
            Console.WriteLine(chavePublica);

            // Calcula e retorna a terceira chave privada D(chave que utiliza para DESCRIPTOGRAFAR)
            d = criptografer.CalcularInversoD(totienteN);
            chavePrivada = criptografer.RetornaChavePrivada(d, moduloN);

            // Imprime para o usuário a chave de descriptografia
            Console.WriteLine("\nChave Privada:");
            Console.WriteLine(chavePrivada);

            return true;
        }

        public static bool OpcaoCriptografia(ref RSACriptUnip criptografer)
        {
            string chavePublica;
            string textoOriginal, textoCifrado = "";

            // Solicita para o usuário digitar um texto
            Console.WriteLine("\nDigite um texto, tudo em maiúsculo, para criptografar.");
            Console.WriteLine("Obs: Ele deve conter no máximo 128 caracteres e não pode conter acento.");

            // Pega o texto digitado
            textoOriginal = Console.ReadLine();

            // Verifica se o usuário digitou corretamente até 128 caracteres
            if (textoOriginal.Length >= 128)
            {
                // Caso tenha digitado igual ou mais de 128, exibe mensagem de erro e reinicia
                Console.WriteLine(TEXTO_MAIOR_QUE_128_RETORNA_PRINCIPAL);
                return false;
            }

            // Solicita a chave de criptografia
            Console.WriteLine("\nDigite a Chave Pública:");
            chavePublica = Console.ReadLine();

            // Realiza a criptografia do texto digitado fornecendo a chave pública
            textoCifrado = criptografer.Criptografar(textoOriginal, chavePublica);

            // Imprime os controles de decisões
            Console.WriteLine("\n\n=====================================");
            Console.WriteLine("== TEXTO CRIPTOGRAFADO COM SUCESSO ==");
            Console.WriteLine("=====================================");
            Console.WriteLine("\nGuarde o texto cifrado:");
            Console.WriteLine(textoCifrado);
            Console.WriteLine("\n");

            return true;
        }

        public static bool OpcaoDescriptografia(ref RSACriptUnip criptografer)
        {
            string chavePrivada = "";
            string textoOriginal = "", textoCifrado = "";

            // Solicita para o usuário digitar um texto
            Console.WriteLine("\nDigite um texto para descriptografar:");

            // Pega o texto digitado
            textoCifrado = Console.ReadLine();

            // Solicita a chave de descriptografia
            Console.WriteLine("\nDigite a Chave Privada:");
            chavePrivada = Console.ReadLine();

            // Realiza a criptografia do texto digitado fornecendo a chave de criptografia
            textoOriginal = criptografer.Descriptografar(textoCifrado, chavePrivada);

            // Imprime os controles de decisões
            Console.WriteLine("\n\n========================================");
            Console.WriteLine("== TEXTO DESCRIPTOGRAFADO COM SUCESSO ==");
            Console.WriteLine("========================================");
            Console.WriteLine("\nTexto original:");
            Console.WriteLine(textoOriginal);
            Console.WriteLine("\n");

            return true;
        }

        public static bool VerificaPrimo(int num)
        {
            bool primo = false;
            int resto, totalDivisores = 0;

            // loop para verificar se o número é primo
            for (int i = 1; i <= num; i++)
            {
                // Calcula o resto da divisao do número pelo index
                resto = num % i;

                // Se possuir resto 0, aumenta o número de divisores (para ser primo precisa se dividr apenas por 1 e ele mesmo)
                if (resto == 0)
                {
                    // Iteração de total de divisores
                    totalDivisores++;
                }
            }

            // Se possuir até 2 divisores (se n = 1 então possui apenas 1 divisor)
            if (totalDivisores <= 2)
            {
                // Caso haja até 2 divisores, então seta que é primo
                primo = true;
            }

            return primo;
        }

        public static bool PerguntaDesejaContinuar(bool repete)
        {
            char charResposta;
            bool retorno = false;

            // Se deu algum erro, repete
            while (repete == true)
            {
                // Pergunta para o usuário se deseja continuar
                Console.WriteLine("\nDeseja continuar no programa? S/N");

                // Tenta converter o charResposta
                if (!char.TryParse(Console.ReadLine(), out charResposta))
                {
                    // Caso tenha ocorrido um erro ao tentar converter o valor para inteiro, exibe uma mensagem de erro e pergunta de novo
                    Console.WriteLine("Valor digitado não corresponde com a resposta. Digitar somente 1 caractere!");
                    repete = true;
                }

                switch (charResposta)
                {
                    case 'S':
                    case 's':
                        // Não manda repetir
                        repete = false;

                        // Retorna SIM
                        retorno = false;

                        break;

                    case 'N':
                    case 'n':
                        // Não manda repetir
                        repete = false;

                        // retorna NÃO
                        retorno = true;

                        break;

                    default:
                        // Caso o usuário não tenha digitado nenhuma das opções
                        Console.WriteLine("Valor digitado não corresponde com as opções. Digite S ou N!");
                        repete = true;

                        break;
                }
            }

            return retorno;
        }
    }
}
